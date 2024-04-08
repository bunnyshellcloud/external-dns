package custom

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"sigs.k8s.io/external-dns/provider/aws"
	"sigs.k8s.io/external-dns/provider/cloudflare"
	"strings"
)

const OriginalTargetLabelKey = "external-dns-custom/original-target"

// CustomProvider is a custom implementation
type CustomProvider struct {
	provider.BaseProvider

	cfProvider  *cloudflare.CloudFlareProvider
	awsProvider *aws.AWSProvider

	awsTargetSuffix  string
	cfTargetOverride string

	txtPrefix         string
	txtSuffix         string
	txtEncryptEnabled bool
	txtEncryptAESKey  []byte
}

// NewCustomProvider initializes a new Custom Provider.
func NewCustomProvider(
	cloudFlareProvider *cloudflare.CloudFlareProvider,
	awsProvider *aws.AWSProvider,
	cloudFlareTargetOverride string,
	awsTargetSuffix string,

	registry,
	txtPrefix,
	txtSuffix string,
	txtEncryptEnabled bool,
	txtEncryptAESKey []byte,
) (*CustomProvider, error) {
	if !awsProvider.PreferCNAME() {
		return nil, fmt.Errorf("failed to initialize custom provider, the AWS Provider must have aws-prefer-cname enabled")
	}

	if !cloudFlareProvider.ProxiedByDefault() {
		return nil, fmt.Errorf("failed to initialize custom provider, the CloudFlare Provider must have cloudflare-proxied enabled")
	}

	if registry != "txt" {
		return nil, fmt.Errorf("failed to initialize custom provider, only TXT registry supported")
	}

	if len(txtEncryptAESKey) == 0 {
		txtEncryptAESKey = nil
	} else if len(txtEncryptAESKey) != 32 {
		return nil, fmt.Errorf("the AES Encryption key must have a length of 32 bytes")
	}
	if txtEncryptEnabled && txtEncryptAESKey == nil {
		return nil, fmt.Errorf("the AES Encryption key must be set when TXT record encryption is enabled")
	}

	if len(txtPrefix) > 0 && len(txtSuffix) > 0 {
		return nil, fmt.Errorf("txt-prefix and txt-suffix are mutual exclusive")
	}

	if txtPrefix != "" {
		log.Infof("Using txtPrefix=%s, make sure is the same one set on the external-dns controller", txtPrefix)
	}
	if txtSuffix != "" {
		log.Infof("Using txtSuffix=%s, make sure is the same one set on the external-dns controller", txtSuffix)
	}

	provider := &CustomProvider{
		awsProvider: awsProvider,
		cfProvider:  cloudFlareProvider,

		awsTargetSuffix:  awsTargetSuffix,
		cfTargetOverride: cloudFlareTargetOverride,

		txtPrefix:         txtPrefix,
		txtSuffix:         txtSuffix,
		txtEncryptEnabled: txtEncryptEnabled,
		txtEncryptAESKey:  txtEncryptAESKey,
	}
	return provider, nil
}

// Records returns the list of records.
func (p *CustomProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	// consider AWSProvider the main source for records
	endpoints, err := p.awsProvider.Records(ctx)
	if err != nil {
		return nil, err
	}

	originalTargetMap := p.getOriginalTargetMap(endpoints)
	for _, endpointItem := range endpoints {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			continue
		}

		if originalTarget, ok := originalTargetMap[endpointItem.DNSName]; ok {
			// we work only with AWS + aws-prefer-cname, so the endpoints will normally have only one target
			endpointItem.Targets = []string{originalTarget}
		}
	}

	return endpoints, err
}

// ApplyChanges applies a given set of changes in a given zone.
func (p *CustomProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	log.Infof("AWS ApplyChanges ...")

	var awsChangesCreate []*endpoint.Endpoint
	awsChangesCreateOriginalMap := getTargetMap(changes.Create)
	for _, endpointItem := range changes.Create {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			awsChangesCreate = append(awsChangesCreate, p.newTXTEndpoint(endpointItem, awsChangesCreateOriginalMap))
			continue
		}

		target := endpointItem.DNSName + p.awsTargetSuffix
		awsChangesCreate = append(awsChangesCreate, newEndpointWithTarget(endpointItem, target))
	}

	var awsChangesUpdateOld []*endpoint.Endpoint
	awsChangesUpdateOldOriginalMap := getTargetMap(changes.UpdateOld)
	for _, endpointItem := range changes.UpdateOld {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			awsChangesUpdateOld = append(awsChangesUpdateOld, p.newTXTEndpoint(endpointItem, awsChangesUpdateOldOriginalMap))
			continue
		}

		target := endpointItem.DNSName + p.awsTargetSuffix
		awsChangesUpdateOld = append(awsChangesUpdateOld, newEndpointWithTarget(endpointItem, target))
	}

	var awsChangesUpdateNew []*endpoint.Endpoint
	awsChangesUpdateNewOriginalMap := getTargetMap(changes.UpdateNew)
	for _, endpointItem := range changes.UpdateNew {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			awsChangesUpdateNew = append(awsChangesUpdateNew, p.newTXTEndpoint(endpointItem, awsChangesUpdateNewOriginalMap))
			continue
		}

		target := endpointItem.DNSName + p.awsTargetSuffix
		awsChangesUpdateNew = append(awsChangesUpdateNew, newEndpointWithTarget(endpointItem, target))
	}

	var awsChangesDelete []*endpoint.Endpoint
	awsChangesDeleteOriginalMap := getTargetMap(changes.Delete)
	for _, endpointItem := range changes.Delete {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			awsChangesDelete = append(awsChangesDelete, p.newTXTEndpoint(endpointItem, awsChangesDeleteOriginalMap))
			continue
		}

		target := endpointItem.DNSName + p.awsTargetSuffix
		awsChangesDelete = append(awsChangesDelete, newEndpointWithTarget(endpointItem, target))
	}

	var awsChanges plan.Changes
	awsChanges.Create = awsChangesCreate
	awsChanges.UpdateOld = awsChangesUpdateOld
	awsChanges.UpdateNew = awsChangesUpdateNew
	awsChanges.Delete = awsChangesDelete

	awsErr := p.awsProvider.ApplyChanges(ctx, &awsChanges)

	if awsErr != nil {
		log.Errorf("AWS ApplyChanges failed, skip Cloudflare ApplyChanges")

		return awsErr
	}

	log.Infof("Cloudflare ApplyChanges ...")
	var cloudflareChangesCreate []*endpoint.Endpoint
	for _, endpointItem := range changes.Create {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			cloudflareChangesCreate = append(cloudflareChangesCreate, endpointItem)
			continue
		}

		target := p.cfTargetOverride
		cloudflareChangesCreate = append(cloudflareChangesCreate, newEndpointWithTarget(endpointItem, target))
	}

	var cloudflareChangesUpdateOld []*endpoint.Endpoint
	for _, endpointItem := range changes.UpdateOld {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			cloudflareChangesUpdateOld = append(cloudflareChangesUpdateOld, endpointItem)
			continue
		}

		target := p.cfTargetOverride
		cloudflareChangesUpdateOld = append(cloudflareChangesUpdateOld, newEndpointWithTarget(endpointItem, target))
	}

	var cloudflareChangesUpdateNew []*endpoint.Endpoint
	for _, endpointItem := range changes.UpdateNew {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			cloudflareChangesUpdateNew = append(cloudflareChangesUpdateNew, endpointItem)
			continue
		}

		target := p.cfTargetOverride
		cloudflareChangesUpdateNew = append(cloudflareChangesUpdateNew, newEndpointWithTarget(endpointItem, target))
	}

	var cloudflareChangesDelete []*endpoint.Endpoint
	for _, endpointItem := range changes.Delete {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			cloudflareChangesDelete = append(cloudflareChangesDelete, endpointItem)
			continue
		}

		target := p.cfTargetOverride
		cloudflareChangesDelete = append(cloudflareChangesDelete, newEndpointWithTarget(endpointItem, target))
	}

	var cloudflareChanges plan.Changes
	cloudflareChanges.Create, _ = p.cfProvider.AdjustEndpoints(cloudflareChangesCreate)
	cloudflareChanges.UpdateOld, _ = p.cfProvider.AdjustEndpoints(cloudflareChangesUpdateOld)
	cloudflareChanges.UpdateNew, _ = p.cfProvider.AdjustEndpoints(cloudflareChangesUpdateNew)
	cloudflareChanges.Delete, _ = p.cfProvider.AdjustEndpoints(cloudflareChangesDelete)

	cfErr := p.cfProvider.ApplyChanges(ctx, &cloudflareChanges)
	if cfErr != nil {
		log.Errorf("Cloudflare ApplyChanges failed")
	} else {
		log.Infof("Cloudflare ApplyChanges OK")
	}

	return cfErr
}

func (p *CustomProvider) newTXTEndpoint(endpointItem *endpoint.Endpoint, originalTargetMap map[string]string) *endpoint.Endpoint {
	targets := endpointItem.Targets
	dnsName := getDNSNameFromTXTName(endpointItem.DNSName, p.txtPrefix, p.txtSuffix)
	if originalTarget, ok := originalTargetMap[dnsName]; ok {
		if labels, err := endpoint.NewLabelsFromString(targets[0], p.txtEncryptAESKey); err == nil {
			labels[OriginalTargetLabelKey] = originalTarget
			targets[0] = labels.Serialize(true, p.txtEncryptEnabled, p.txtEncryptAESKey)
		} else {
			log.Warningf("could not extract labels from TXT target: %v", err)
		}
	}

	return newEndpoint(
		endpointItem.DNSName,
		endpointItem.RecordType,
		endpointItem.SetIdentifier,
		endpointItem.RecordTTL,
		targets,
		endpointItem.Labels,
		endpointItem.ProviderSpecific,
	)
}

func getDNSNameFromTXTName(txtName, txtPrefix, txtSuffix string) string {
	if txtPrefix != "" && strings.HasPrefix(txtName, txtPrefix) {
		return txtName[len(txtPrefix):]
	}

	if txtSuffix != "" && strings.HasSuffix(txtName, txtSuffix) {
		return txtName[:len(txtName)-len(txtPrefix)]
	}

	return txtName
}

func newEndpointWithTarget(endpointItem *endpoint.Endpoint, target string) *endpoint.Endpoint {
	return newEndpoint(
		endpointItem.DNSName,
		endpointItem.RecordType,
		endpointItem.SetIdentifier,
		endpointItem.RecordTTL,
		[]string{target},
		endpointItem.Labels,
		endpoint.ProviderSpecific{}, // should be recomputed after this to pick up the changes
	)
}

func newEndpoint(dnsName, recordType, setIdentifier string, ttl endpoint.TTL, targets []string, labels endpoint.Labels, providerSpecific endpoint.ProviderSpecific) *endpoint.Endpoint {
	return &endpoint.Endpoint{
		DNSName:          dnsName,
		Targets:          targets,
		RecordType:       recordType,
		SetIdentifier:    setIdentifier,
		RecordTTL:        ttl,
		Labels:           labels,
		ProviderSpecific: providerSpecific,
	}
}

func getTargetMap(endpointItems []*endpoint.Endpoint) map[string]string {
	targetMap := make(map[string]string)
	for _, endpointItem := range endpointItems {
		if endpointItem.RecordType == endpoint.RecordTypeTXT {
			continue
		}

		// we work only with AWS + aws-prefer-cname, so the endpoints will normally have only one target
		targetMap[endpointItem.DNSName] = endpointItem.Targets[0]
	}

	return targetMap
}

func (p *CustomProvider) getOriginalTargetMap(endpointItems []*endpoint.Endpoint) map[string]string {
	originalTargetMap := make(map[string]string)
	for _, endpointItem := range endpointItems {
		if endpointItem.RecordType != endpoint.RecordTypeTXT {
			continue
		}

		labels, err := endpoint.NewLabelsFromString(endpointItem.Targets[0], p.txtEncryptAESKey)
		if err != nil {
			log.Warningf("could not extract labels from TXT target: %v", err)

			continue
		}

		if originalTarget, ok := labels[OriginalTargetLabelKey]; ok {
			dnsName := getDNSNameFromTXTName(endpointItem.DNSName, p.txtPrefix, p.txtSuffix)
			originalTargetMap[dnsName] = originalTarget
		}
	}

	return originalTargetMap
}

// AdjustEndpoints modifies the endpoints as needed by the specific provider
func (p *CustomProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	// consider AWSProvider the main source, we returned the list of record from AWS we should apply AWS adjustments
	return p.awsProvider.AdjustEndpoints(endpoints)
}

// GetDomainFilter generates a filter to exclude any domain that is not controlled by the provider
func (p *CustomProvider) GetDomainFilter() endpoint.DomainFilter {
	// consider AWSProvider the main source for records and domains
	return p.awsProvider.GetDomainFilter()
}
