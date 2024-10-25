// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Gabriele Genovese",
            "email": "gabriele.genovese2@studio.unibo.it"
        },
        "license": {
            "name": "AGPL-3.0",
            "url": "https://www.gnu.org/licenses/agpl-3.0.en.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/login": {
            "get": {
                "description": "LoginHandler handles login requests, redirecting the web client to GitHub's first stage\nfor the OAuth flow, where the user has to grant access to the specified scopes",
                "tags": [
                    "login"
                ],
                "summary": "Login user",
                "parameters": [
                    {
                        "type": "string",
                        "description": "url to redirect if login is successful",
                        "name": "redirect_uri",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/util.ApiError"
                        }
                    }
                }
            }
        },
        "/login/callback": {
            "get": {
                "description": "CallbackHandler handles the OAuth callback, obtaining the GitHub's Bearer token\nfor the logged-in user, and generating a wrapper JWT for our session.",
                "tags": [
                    "login"
                ],
                "summary": "Login Callback",
                "parameters": [
                    {
                        "type": "string",
                        "description": "code query parameter",
                        "name": "code",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "url to redirect if login is successful",
                        "name": "redirect_uri",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/util.ApiError"
                        }
                    }
                }
            }
        },
        "/logout": {
            "get": {
                "description": "Reset the cookie",
                "tags": [
                    "login"
                ],
                "summary": "Logout user",
                "parameters": [
                    {
                        "type": "string",
                        "description": "url to redirect if login is successful",
                        "name": "redirect_uri",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/util.ApiError"
                        }
                    }
                }
            }
        },
        "/whoami": {
            "get": {
                "description": "Return user information if logged in",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "login"
                ],
                "summary": "Who am I",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/auth.User"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "auth.User": {
            "type": "object",
            "properties": {
                "admin": {
                    "type": "boolean"
                },
                "avatarUrl": {
                    "type": "string"
                },
                "email": {
                    "type": "string"
                },
                "name": {
                    "type": "string"
                },
                "username": {
                    "type": "string"
                }
            }
        },
        "util.ApiError": {
            "type": "object",
            "properties": {
                "error": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/",
	Schemes:          []string{},
	Title:            "Login cs github service API",
	Description:      "This is a service to handle the login of a user for the cartabinaria organisation's web-applications.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
