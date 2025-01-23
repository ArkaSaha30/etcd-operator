package certificate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	ecv1alpha1 "go.etcd.io/etcd-operator/api/v1alpha1"
)

type NewCertificateManager struct {
	Ctx         context.Context
	Client      client.Client
	Scheme      *runtime.Scheme
	EtcdCluster *ecv1alpha1.EtcdCluster
	CertProvider
}

type CertProvider interface {
	CertManager
}

type CertManager interface {
	GetCMCertificate()
	CreateCMCertificate()
}

func (c *NewCertificateManager) GetCMCertificate(tlsCertName, namespace string) (*certv1.Certificate, error) {
	foundCert := &certv1.Certificate{}

	err := c.Client.Get(c.Ctx, client.ObjectKey{Name: tlsCertName, Namespace: namespace}, foundCert)
	if err != nil {
		return nil, err
	}
	return foundCert, nil
}

func (c *NewCertificateManager) CreateCMCertificate(tlsCertName string) (*certv1.Certificate, error) {
	certificateResource := &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tlsCertName,
			Namespace: c.EtcdCluster.Namespace,
		},
		Spec: certv1.CertificateSpec{
			SecretName: tlsCertName,
			DNSNames:   []string{fmt.Sprintf("%s-%d.%s.%s.svc.cluster.local", c.EtcdCluster.Name, c.EtcdCluster.Spec.Size, c.EtcdCluster.Name, c.EtcdCluster.Namespace)},
			IssuerRef: cmmeta.ObjectReference{
				Name: CMClusterIssuerName,
				Kind: "ClusterIssuer",
			},
		},
	}

	err := c.Client.Create(c.Ctx, certificateResource)
	if err != nil {
		return nil, err
	}
	return certificateResource, nil
}

func setCertificateFuncs(c NewCertificateManager) (func(string, string) (*certv1.Certificate, error), func(string) (*certv1.Certificate, error), error) {
	certProvider := c.EtcdCluster.Spec.TLS.Provider

	switch certProvider {
	case "cert-manager":
		return c.GetCMCertificate, c.CreateCMCertificate, nil
	default:
		return nil, nil, errors.New("invalid certificate provider")

	}
}

func ReconcileMemberCertificate(c NewCertificateManager) ([]interface{}, error) {
	var certificates []interface{}
	logger := log.FromContext(c.Ctx)

	getCertFunc, createCertFunc, err := setCertificateFuncs(c)
	if err != nil {
		return nil, err
	}

	for members := 1; members <= c.EtcdCluster.Spec.Size; members++ {

		clientCertName := strings.Join([]string{c.EtcdCluster.Name, c.EtcdCluster.Spec.TLS.OperatorSecret, fmt.Sprintf("%d", members)}, "-")
		logger.Info("Starting reconciliation of Client Certificate", clientCertName, c.EtcdCluster.Namespace)
		clientCert, clientCertErr := getCertFunc(clientCertName, c.EtcdCluster.Namespace)
		if k8serrors.IsNotFound(clientCertErr) {
			clientCert, clientCertErr = createCertFunc(clientCertName)
			if clientCertErr != nil {
				logger.Error(clientCertErr, "failed to create Client Certificate")
			}
		} else {
			logger.Error(clientCertErr, "failed to get Client Certificate")
		}

		peerCertName := strings.Join([]string{c.EtcdCluster.Name, c.EtcdCluster.Spec.TLS.Member.PeerSecret, fmt.Sprintf("%d", members)}, "-")
		logger.Info("Starting reconciliation of Peer Certificate", peerCertName, c.EtcdCluster.Namespace)
		peerCert, peerCertErr := getCertFunc(peerCertName, c.EtcdCluster.Namespace)
		if k8serrors.IsNotFound(peerCertErr) {
			peerCert, peerCertErr = createCertFunc(peerCertName)
			if peerCertErr != nil {
				logger.Error(peerCertErr, "failed to create Peer Certificate")
			}
		} else {
			logger.Error(clientCertErr, "failed to get Peer Certificate")
		}

		certificates = append(certificates, clientCert, peerCert)
	}

	for _, cert := range certificates {
		if cert == nil {
			return certificates, errors.New("failed to create one or more certificate")
		}
	}
	return certificates, nil
}

func ReconcileServerCertificate(c NewCertificateManager) (interface{}, error) {
	var serverCert interface{}
	logger := log.FromContext(c.Ctx)

	getCertFunc, createCertFunc, err := setCertificateFuncs(c)
	if err != nil {
		return nil, err
	}

	serverCertName := strings.Join([]string{c.EtcdCluster.Name, c.EtcdCluster.Spec.TLS.Member.ServerSecret}, "-")
	logger.Info("Starting reconciliation of Server Certificate", serverCertName, c.EtcdCluster.Namespace)
	_, serverCertErr := getCertFunc(serverCertName, c.EtcdCluster.Namespace)
	if k8serrors.IsNotFound(serverCertErr) {
		serverCert, serverCertErr = createCertFunc(serverCertName)
		if serverCertErr != nil {
			logger.Error(serverCertErr, "failed to create Server Certificate")
			return nil, serverCertErr
		}
	} else {
		logger.Error(serverCertErr, "failed to get Server Certificate")
		return nil, serverCertErr
	}

	return serverCert, nil
}
