module github.com/DavyLandman/sliot/test

go 1.14

replace github.com/DavyLandman/sliot/server => ../server

require (
	github.com/DavyLandman/sliot/server v0.0.0-00010101000000-000000000000
	github.com/pkg/profile v1.5.0
)
