module github.com/DavyLandman/sliot/test

go 1.13

replace github.com/DavyLandman/sliot/server => ../server

require (
	github.com/DavyLandman/sliot/server v0.0.0-20200109201230-8451d88f88b9
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/pkg/profile v1.5.0 // indirect
)
