package web

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"emperror.dev/errors"
	"fmt"
	"github.com/bluele/gcache"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/je4/utils/v2/pkg/zLogger"
	"github.com/je4/vod/pkg/web/docs"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const BASEPATH = "/api/v1"

//	@title			Video on Delay API
//	@version		1.0
//	@description	Video on Delay API for playback of video streams with delay
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	Jürgen Enge
//	@contact.email	juergen@info-age.net

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

func NewMainController(addr string, extAddr string, tlsConfig *tls.Config, jwtKey string, jwtAlg []string, cacheExpiration time.Duration, logger zLogger.ZLogger) (*MainController, error) {
	u, err := url.Parse(extAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid external address '%s'", extAddr)
	}
	subpath := "/" + strings.Trim(u.Path, "/")
	// programmatically set swagger info
	docs.SwaggerInfoVODAPI.Host = strings.TrimRight(fmt.Sprintf("%s:%s", u.Hostname(), u.Port()), " :")
	docs.SwaggerInfoVODAPI.BasePath = "/" + strings.Trim(subpath+BASEPATH, "/")
	docs.SwaggerInfoVODAPI.Schemes = []string{"https"}

	gin.SetMode(gin.DebugMode)
	ctrl := &MainController{
		addr:      addr,
		extAddr:   extAddr,
		tlsConfig: tlsConfig,
		router:    gin.Default(),
		jwtAlg:    jwtAlg,
		jwtKey:    jwtKey,
		cache:     gcache.New(100).LRU().Expiration(cacheExpiration).Build(),
		logger:    logger,
	}
	return ctrl, ctrl.Init()
}

type MainController struct {
	addr      string
	extAddr   string
	tlsConfig *tls.Config
	router    *gin.Engine
	alg       []string
	cache     gcache.Cache
	jwtAlg    []string
	jwtKey    string
	logger    zLogger.ZLogger
	server    *http.Server
}

type VODClaims struct {
	jwt.RegisteredClaims
	SHA1 string `json:"sha1,omitempty"`
}

func (ctrl *MainController) Init() error {
	v1 := ctrl.router.Group(BASEPATH)

	v1.GET("/ping", ctrl.ping)

	v1.Use(func(c *gin.Context) {
		var tokenString string
		authHeader := c.Request.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			if c.Request.URL.Query().Get("token") != "" {
				tokenString = c.Request.URL.Query().Get("token")
			}
		}
		tokenString = strings.TrimSpace(tokenString)
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, HTTPResultMessage{
				Code:    http.StatusUnauthorized,
				Message: "no token found",
			})
			return
		}
		token, err := jwt.ParseWithClaims(tokenString, &VODClaims{}, func(token *jwt.Token) (interface{}, error) {
			return ctrl.jwtKey, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, HTTPResultMessage{
				Code:    http.StatusUnauthorized,
				Message: fmt.Sprintf("cannot parse token: %v", err),
			})
			return
		}
		if !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, HTTPResultMessage{
				Code:    http.StatusUnauthorized,
				Message: "invalid token",
			})
			return
		}
		claims, ok := token.Claims.(*VODClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, HTTPResultMessage{
				Code:    http.StatusUnauthorized,
				Message: "invalid token claims",
			})
			return
		}
		c.Set("jwtSubject", claims.Subject)
		c.Set("jwtSHA1", claims.SHA1)
		c.Next()
	})
	ctrl.router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.NewHandler(), ginSwagger.InstanceName("VODAPI")))
	//ctrl.router.StaticFS("/swagger/", http.FS(swaggerFiles.FS))

	ctrl.server = &http.Server{
		Addr:      ctrl.addr,
		Handler:   ctrl.router,
		TLSConfig: ctrl.tlsConfig,
	}
	return nil
}

func (ctrl *MainController) Start(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ctrl.server.TLSConfig != nil {
			ctrl.logger.Info().Msgf("starting https server on %s", ctrl.addr)
			if err := ctrl.server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				ctrl.logger.Fatal().Err(err).Msg("cannot start https server")
			}
		} else {
			ctrl.logger.Info().Msgf("starting http server on %s", ctrl.addr)
			if err := ctrl.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				ctrl.logger.Fatal().Err(err).Msg("cannot start http server")
			}
		}
	}()
}

func (ctrl *MainController) GracefulStop() {
	if err := ctrl.server.Shutdown(context.Background()); err != nil {
		ctrl.logger.Error().Err(err).Msg("cannot shutdown server")
	}
}

// ping godoc
// @Summary      does pong
// @ID			 get-ping
// @Description  for testing if server is running
// @Tags         vod
// @Produce      plain
// @Success      200  {string}  string
// @Router       /ping [get]
func (ctrl *MainController) ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

type StoreRequest struct {
	ObjectSignature string   `json:"object_signature"`
	MediaSignature  []string `json:"media_signature" binding:"required"`
	Start           string   `json:"start" binding:"required"`
	End             string   `json:"end"`
}

func (ctrl *MainController) store(c *gin.Context) {
	var req = &StoreRequest{}
	if err := c.Bind(req); err != nil {
		NewResultMessage(c, http.StatusBadRequest, err)
		return
	}
	if req.End == "" {
		req.End = req.Start
	}
	start, err := time.Parse(time.RFC3339, req.Start)
	if err != nil {
		NewResultMessage(c, http.StatusBadRequest, errors.Wrapf(err, "invaid start time '%s'", req.Start))
		return
	}
	end, err := time.Parse(time.RFC3339, req.End)
	if err != nil {
		NewResultMessage(c, http.StatusBadRequest, errors.Wrapf(err, "invaid end time '%s'", req.End))
		return
	}
	if end.Before(start) {
		NewResultMessage(c, http.StatusBadRequest, errors.New("end time before start time"))
		return
	}
	if len(req.MediaSignature) == 0 {
		NewResultMessage(c, http.StatusBadRequest, errors.New("no media signature"))
		return
	}
	jwtSubject := c.GetString("jwtSubject")
	if jwtSubject != "store" {
		NewResultMessage(c, http.StatusUnauthorized, errors.Errorf("invalid jwt subject '%s' for store ", jwtSubject))
		return
	}
	sha1Str := c.GetString("jwtSHA1")
	if sha1Str == "" {
		NewResultMessage(c, http.StatusUnauthorized, errors.New("no sha1 in token"))
		return
	}
	sha1Str2 := fmt.Sprintf("%x", sha1.Sum([]byte(strings.ToLower(strings.Join(append([]string{req.ObjectSignature}, req.MediaSignature...), ".")))))
	if sha1Str != sha1Str2 {
		NewResultMessage(c, http.StatusUnauthorized, errors.Errorf("sha1 mismatch: '%s' != '%s'", sha1Str, sha1Str2))
		return
	}

}
