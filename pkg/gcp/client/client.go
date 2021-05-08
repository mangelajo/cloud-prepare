/*
© 2021 Red Hat, Inc. and others.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package client

import (
	"context"

	"golang.org/x/oauth2/google"

	compute "google.golang.org/api/compute/v1"
	dns "google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

//go:generate mockgen -source=./client.go -destination=./mock/client_generated.go -package=mock

// Interface wraps an actual GCP library client to allow for easier testing.
type Interface interface {
	GetProjectID() string
	InsertFirewallRule(rule *compute.Firewall) error
	GetFirewallRule(name string) (*compute.Firewall, error)
	DeleteFirewallRule(name string) error
	UpdateFirewallRule(name string, rule *compute.Firewall) error
}

type gcpClient struct {
	projectID     string
	computeClient *compute.Service
}

func (g *gcpClient) GetProjectID() string {
	return g.projectID
}

func (g *gcpClient) InsertFirewallRule(rule *compute.Firewall) error {
	_, err := g.computeClient.Firewalls.Insert(g.projectID, rule).Context(context.TODO()).Do()
	return err
}

func (g *gcpClient) GetFirewallRule(name string) (*compute.Firewall, error) {
	return g.computeClient.Firewalls.Get(g.projectID, name).Context(context.TODO()).Do()
}

func (g *gcpClient) DeleteFirewallRule(name string) error {
	_, err := g.computeClient.Firewalls.Delete(g.projectID, name).Context(context.TODO()).Do()
	return err
}

func (g *gcpClient) UpdateFirewallRule(name string, rule *compute.Firewall) error {
	_, err := g.computeClient.Firewalls.Update(g.projectID, name, rule).Context(context.TODO()).Do()
	return err
}

func NewClient(authJSON []byte) (Interface, error) {
	ctx := context.TODO()

	creds, err := google.CredentialsFromJSON(ctx, authJSON, dns.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	options := []option.ClientOption{
		option.WithCredentials(creds),
	}
	computeClient, err := compute.NewService(ctx, options...)
	if err != nil {
		return nil, err
	}

	return &gcpClient{
		projectID:     creds.ProjectID,
		computeClient: computeClient,
	}, nil
}
