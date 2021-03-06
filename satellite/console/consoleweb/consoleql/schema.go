// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package consoleql

import (
	"sync"

	"github.com/graphql-go/graphql"

	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/mailservice"
)

// creatingSchemaMutex locks graphql.NewSchema method because it's not thread-safe
var creatingSchemaMutex sync.Mutex

// CreateSchema creates both type
func CreateSchema(service *console.Service, mailService *mailservice.Service) (graphql.Schema, error) {
	creatingSchemaMutex.Lock()
	defer creatingSchemaMutex.Unlock()

	creator := TypeCreator{}
	err := creator.Create(service, mailService)
	if err != nil {
		return graphql.Schema{}, err
	}

	return graphql.NewSchema(graphql.SchemaConfig{
		Query:    creator.RootQuery(),
		Mutation: creator.RootMutation(),
	})
}
