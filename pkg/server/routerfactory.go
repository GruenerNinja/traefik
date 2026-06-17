package server

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/config/static"
	httpmuxer "github.com/traefik/traefik/v3/pkg/muxer/http"
	"github.com/traefik/traefik/v3/pkg/server/middleware"
	tcpmiddleware "github.com/traefik/traefik/v3/pkg/server/middleware/tcp"
	"github.com/traefik/traefik/v3/pkg/server/router"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	udprouter "github.com/traefik/traefik/v3/pkg/server/router/udp"
	"github.com/traefik/traefik/v3/pkg/server/service"
	tcpsvc "github.com/traefik/traefik/v3/pkg/server/service/tcp"
	udpsvc "github.com/traefik/traefik/v3/pkg/server/service/udp"
	"github.com/traefik/traefik/v3/pkg/tcp"
	"github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/udp"
)

// RouterFactory the factory of TCP/UDP routers.
type RouterFactory struct {
	entryPointsTCP []string
	entryPointsUDP []string

	allowACMEByPass map[string]bool

	managerFactory *service.ManagerFactory

	pluginBuilder middleware.PluginsBuilder

	observabilityMgr *middleware.ObservabilityMgr
	tlsManager       *tls.Manager

	dialerManager              *tcp.DialerManager
	tlsFallbackCaches          map[string]*tcprouter.TLSFallbackCache
	tlsFallbackRouteSignatures map[string]string

	cancelPrevState func()

	parser              httpmuxer.SyntaxParser
	providersPrecedence []string
}

// NewRouterFactory creates a new RouterFactory.
func NewRouterFactory(staticConfiguration static.Configuration, managerFactory *service.ManagerFactory, tlsManager *tls.Manager,
	observabilityMgr *middleware.ObservabilityMgr, pluginBuilder middleware.PluginsBuilder, dialerManager *tcp.DialerManager,
) (*RouterFactory, error) {
	handlesTLSChallenge := false
	for _, resolver := range staticConfiguration.CertificatesResolvers {
		if resolver.ACME != nil && resolver.ACME.TLSChallenge != nil {
			handlesTLSChallenge = true
			break
		}
	}

	allowACMEByPass := map[string]bool{}
	var entryPointsTCP, entryPointsUDP []string
	for name, ep := range staticConfiguration.EntryPoints {
		allowACMEByPass[name] = ep.AllowACMEByPass || !handlesTLSChallenge

		protocol, err := ep.GetProtocol()
		if err != nil {
			// Should never happen because Traefik should not start if protocol is invalid.
			log.Error().Err(err).Msg("Invalid protocol")
		}

		if protocol == "udp" {
			entryPointsUDP = append(entryPointsUDP, name)
		} else {
			entryPointsTCP = append(entryPointsTCP, name)
		}
	}

	parser, err := httpmuxer.NewSyntaxParser()
	if err != nil {
		return nil, fmt.Errorf("creating parser: %w", err)
	}

	var providersPrecedence []string
	if staticConfiguration.Providers != nil {
		providersPrecedence = staticConfiguration.Providers.Precedence
	}

	return &RouterFactory{
		entryPointsTCP:             entryPointsTCP,
		entryPointsUDP:             entryPointsUDP,
		managerFactory:             managerFactory,
		observabilityMgr:           observabilityMgr,
		tlsManager:                 tlsManager,
		pluginBuilder:              pluginBuilder,
		dialerManager:              dialerManager,
		tlsFallbackCaches:          make(map[string]*tcprouter.TLSFallbackCache),
		tlsFallbackRouteSignatures: make(map[string]string),
		allowACMEByPass:            allowACMEByPass,
		parser:                     parser,
		providersPrecedence:        providersPrecedence,
	}, nil
}

// CreateRouters creates new TCPRouters and UDPRouters.
func (f *RouterFactory) CreateRouters(rtConf *runtime.Configuration) (map[string]*tcprouter.Router, map[string]udp.Handler) {
	if f.cancelPrevState != nil {
		f.cancelPrevState()
	}

	var ctx context.Context
	ctx, f.cancelPrevState = context.WithCancel(context.Background())

	// HTTP
	serviceManager := f.managerFactory.Build(rtConf)

	middlewaresBuilder := middleware.NewBuilder(rtConf.Middlewares, serviceManager, f.pluginBuilder)

	serviceManager.SetMiddlewareChainBuilder(middlewaresBuilder)

	routerManager := router.NewManager(rtConf, serviceManager, middlewaresBuilder, f.observabilityMgr, f.tlsManager, f.parser, f.providersPrecedence)

	routerManager.ParseRouterTree()

	handlersNonTLS := routerManager.BuildHandlers(ctx, f.entryPointsTCP, false)
	handlersTLS := routerManager.BuildHandlers(ctx, f.entryPointsTCP, true)

	serviceManager.LaunchHealthCheck(ctx)

	// TCP
	svcTCPManager := tcpsvc.NewManager(rtConf, f.dialerManager)

	middlewaresTCPBuilder := tcpmiddleware.NewBuilder(rtConf.TCPMiddlewares)

	rtTCPManager := tcprouter.NewManager(rtConf, svcTCPManager, middlewaresTCPBuilder, handlersNonTLS, handlersTLS, f.tlsManager, f.providersPrecedence)
	rtTCPManager.SetTLSFallbackCaches(f.getTLSFallbackCaches(rtConf))
	routersTCP := rtTCPManager.BuildHandlers(ctx, f.entryPointsTCP)

	for ep, r := range routersTCP {
		if allowACMEByPass, ok := f.allowACMEByPass[ep]; ok && allowACMEByPass {
			r.EnableACMETLSPassthrough()
		}
	}

	svcTCPManager.LaunchHealthCheck(ctx)

	// UDP
	svcUDPManager := udpsvc.NewManager(rtConf)
	rtUDPManager := udprouter.NewManager(rtConf, svcUDPManager)
	routersUDP := rtUDPManager.BuildHandlers(ctx, f.entryPointsUDP)

	rtConf.PopulateUsedBy()

	return routersTCP, routersUDP
}

func (f *RouterFactory) getTLSFallbackCaches(rtConf *runtime.Configuration) map[string]*tcprouter.TLSFallbackCache {
	caches := make(map[string]*tcprouter.TLSFallbackCache, len(f.entryPointsTCP))
	for _, entryPointName := range f.entryPointsTCP {
		cache := f.tlsFallbackCaches[entryPointName]
		if cache == nil {
			cache = tcprouter.NewTLSFallbackCache()
			f.tlsFallbackCaches[entryPointName] = cache
		}

		signature := tlsFallbackRouteSignature(rtConf, entryPointName)
		if previousSignature, ok := f.tlsFallbackRouteSignatures[entryPointName]; ok && previousSignature != signature {
			cache.Reset()
		}
		f.tlsFallbackRouteSignatures[entryPointName] = signature

		caches[entryPointName] = cache
	}

	return caches
}

func tlsFallbackRouteSignature(rtConf *runtime.Configuration, entryPointName string) string {
	var parts []string

	for routerName, routerConfig := range rtConf.TCPRouters {
		if routerConfig == nil || routerConfig.Fallback || routerConfig.TLS == nil || !slices.Contains(routerConfig.EntryPoints, entryPointName) {
			continue
		}

		parts = append(parts, fmt.Sprintf("tcp:%s:%s:%s:%d", routerName, routerConfig.Rule, routerConfig.RuleSyntax, routerConfig.Priority))
	}

	for routerName, routerConfig := range rtConf.Routers {
		if routerConfig == nil || routerConfig.TLS == nil || !slices.Contains(routerConfig.EntryPoints, entryPointName) {
			continue
		}

		parts = append(parts, fmt.Sprintf("http:%s:%s:%s:%d", routerName, routerConfig.Rule, routerConfig.RuleSyntax, routerConfig.Priority))
	}

	slices.Sort(parts)

	return strings.Join(parts, "\n")
}
