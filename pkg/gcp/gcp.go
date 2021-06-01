/*
SPDX-License-Identifier: Apache-2.0
Copyright Contributors to the Submariner project.
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
package gcp

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/submariner-io/cloud-prepare/pkg/api"
	gcpclient "github.com/submariner-io/cloud-prepare/pkg/gcp/client"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

const (
	publicPortsRuleName   = "submariner-public-ports"
	internalPortsRuleName = "submariner-internal-ports"
)

type gcpCloud struct {
	infraID   string
	projectID string
	client    gcpclient.Interface
}

// NewCloud creates a new api.Cloud instance which can prepare GCP for Submariner to be deployed on it
func NewCloud(infraID string, client gcpclient.Interface) api.Cloud {
	return &gcpCloud{
		infraID:   infraID,
		projectID: client.GetProjectID(),
		client:    client,
	}
}

// PrepareForSubmariner prepares submariner cluster environment on GCP
func (gc *gcpCloud) PrepareForSubmariner(input api.PrepareForSubmarinerInput, reporter api.Reporter) error {
	// create the inbound and outbound firewall rules for submariner public ports
	ingress, egress := gc.newFirewallRules(publicPortsRuleName, input.PublicPorts, false)
	if err := gc.openPorts(ingress, egress); err != nil {
		return fmt.Errorf("failed to open submariner public ports: %v", err)
	}

	reporter.Succeeded("Submariner public ports are opened with firewall rules %q and %q on GCP", ingress.Name, egress.Name)

	// create the inbound firewall rule for submariner internal ports
	internalIngress, _ := gc.newFirewallRules(internalPortsRuleName, input.InternalPorts, true)
	if err := gc.openPorts(internalIngress); err != nil {
		return fmt.Errorf("failed to open submariner internal ports: %v", err)
	}

	reporter.Succeeded("Submariner internal ports are opened with firewall rule %q on GCP", internalIngress.Name)

	return nil
}

// CleanupAfterSubmariner clean up submariner cluster environment on GCP
func (gc *gcpCloud) CleanupAfterSubmariner(reporter api.Reporter) error {
	ingressName, egressName := generateRuleNames(gc.infraID, publicPortsRuleName)
	// delete the inbound and outbound firewall rules to close submariner public ports
	if err := gc.client.DeleteFirewallRule(ingressName); err != nil {
		return err
	}

	if err := gc.client.DeleteFirewallRule(egressName); err != nil {
		return err
	}

	reporter.Succeeded("Submariner public ports are closed on GCP")

	// delete the inbound and outbound firewall rules to close submariner internal ports
	internalIngressName, _ := generateRuleNames(gc.infraID, internalPortsRuleName)
	if err := gc.client.DeleteFirewallRule(internalIngressName); err != nil {
		return err
	}

	reporter.Succeeded("Submariner internal ports are closed on GCP")

	return nil
}

func (gc *gcpCloud) newFirewallRules(name string, ports []api.PortSpec, isInternal bool) (ingress, egress *compute.Firewall) {
	ingressName, egressName := generateRuleNames(gc.infraID, name)

	allowedPorts := []*compute.FirewallAllowed{}
	for _, port := range ports {
		allowedPorts = append(allowedPorts, &compute.FirewallAllowed{
			IPProtocol: port.Protocol,
			Ports:      []string{strconv.Itoa(int(port.Port))},
		})
	}

	ingress = &compute.Firewall{
		Name:      ingressName,
		Network:   fmt.Sprintf("projects/%s/global/networks/%s-network", gc.projectID, gc.infraID),
		Direction: "INGRESS",
		Allowed:   allowedPorts,
	}

	// if ports are internal, we make the ports are accessed in internal cluster and egress is not required
	if isInternal {
		ingress.TargetTags = []string{
			fmt.Sprintf("%s-worker", gc.infraID),
			fmt.Sprintf("%s-master", gc.infraID),
		}
		ingress.SourceTags = []string{
			fmt.Sprintf("%s-worker", gc.infraID),
			fmt.Sprintf("%s-master", gc.infraID),
		}

		return ingress, nil
	}

	return ingress, &compute.Firewall{
		Name:      egressName,
		Network:   fmt.Sprintf("projects/%s/global/networks/%s-network", gc.projectID, gc.infraID),
		Direction: "EGRESS",
		Allowed:   allowedPorts,
	}
}

// open expected ports by creating related firewall rule
// - if the firewall rule is not found, we will create it
// - if the firewall rule is found and changed, we will update it
func (gc *gcpCloud) openPorts(rules ...*compute.Firewall) error {
	for _, rule := range rules {
		current, err := gc.client.GetFirewallRule(rule.Name)
		if gerr, ok := err.(*googleapi.Error); ok && gerr.Code == 404 {
			if err := gc.client.InsertFirewallRule(rule); err != nil {
				return err
			}

			continue
		}

		if err != nil {
			return err
		}

		if !ruleChanged(current, rule) {
			continue
		}

		if err := gc.client.UpdateFirewallRule(rule.Name, rule); err != nil {
			return err
		}
	}

	return nil
}

func generateRuleNames(infraID, name string) (ingressName, egressName string) {
	return fmt.Sprintf("%s-%s-ingress", infraID, name), fmt.Sprintf("%s-%s-egress", infraID, name)
}

func ruleChanged(oldRule, newRule *compute.Firewall) bool {
	if len(oldRule.Allowed) != len(newRule.Allowed) {
		return true
	}

	if oldRule.Allowed[0].IPProtocol != newRule.Allowed[0].IPProtocol {
		return true
	}

	return !reflect.DeepEqual(oldRule.Allowed[0].Ports, newRule.Allowed[0].Ports)
}
