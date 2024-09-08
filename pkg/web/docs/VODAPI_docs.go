// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplateVODAPI = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "http://swagger.io/terms/",
        "contact": {
            "name": "Jürgen Enge",
            "email": "juergen@info-age.net"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/ping": {
            "get": {
                "description": "for testing if server is running",
                "produces": [
                    "text/plain"
                ],
                "tags": [
                    "mediaserver"
                ],
                "summary": "does pong",
                "operationId": "get-ping",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfoVODAPI holds exported Swagger Info so clients can modify it
var SwaggerInfoVODAPI = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "Video on Delay API",
	Description:      "Video on Delay API for playback of video streams with delay",
	InfoInstanceName: "VODAPI",
	SwaggerTemplate:  docTemplateVODAPI,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfoVODAPI.InstanceName(), SwaggerInfoVODAPI)
}
