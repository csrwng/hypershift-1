/*


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
// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/openshift/hypershift/api/karpenter/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// OpenshiftEC2NodeClassLister helps list OpenshiftEC2NodeClasses.
// All objects returned here must be treated as read-only.
type OpenshiftEC2NodeClassLister interface {
	// List lists all OpenshiftEC2NodeClasses in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.OpenshiftEC2NodeClass, err error)
	// OpenshiftEC2NodeClasses returns an object that can list and get OpenshiftEC2NodeClasses.
	OpenshiftEC2NodeClasses(namespace string) OpenshiftEC2NodeClassNamespaceLister
	OpenshiftEC2NodeClassListerExpansion
}

// openshiftEC2NodeClassLister implements the OpenshiftEC2NodeClassLister interface.
type openshiftEC2NodeClassLister struct {
	indexer cache.Indexer
}

// NewOpenshiftEC2NodeClassLister returns a new OpenshiftEC2NodeClassLister.
func NewOpenshiftEC2NodeClassLister(indexer cache.Indexer) OpenshiftEC2NodeClassLister {
	return &openshiftEC2NodeClassLister{indexer: indexer}
}

// List lists all OpenshiftEC2NodeClasses in the indexer.
func (s *openshiftEC2NodeClassLister) List(selector labels.Selector) (ret []*v1beta1.OpenshiftEC2NodeClass, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.OpenshiftEC2NodeClass))
	})
	return ret, err
}

// OpenshiftEC2NodeClasses returns an object that can list and get OpenshiftEC2NodeClasses.
func (s *openshiftEC2NodeClassLister) OpenshiftEC2NodeClasses(namespace string) OpenshiftEC2NodeClassNamespaceLister {
	return openshiftEC2NodeClassNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// OpenshiftEC2NodeClassNamespaceLister helps list and get OpenshiftEC2NodeClasses.
// All objects returned here must be treated as read-only.
type OpenshiftEC2NodeClassNamespaceLister interface {
	// List lists all OpenshiftEC2NodeClasses in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.OpenshiftEC2NodeClass, err error)
	// Get retrieves the OpenshiftEC2NodeClass from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.OpenshiftEC2NodeClass, error)
	OpenshiftEC2NodeClassNamespaceListerExpansion
}

// openshiftEC2NodeClassNamespaceLister implements the OpenshiftEC2NodeClassNamespaceLister
// interface.
type openshiftEC2NodeClassNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all OpenshiftEC2NodeClasses in the indexer for a given namespace.
func (s openshiftEC2NodeClassNamespaceLister) List(selector labels.Selector) (ret []*v1beta1.OpenshiftEC2NodeClass, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.OpenshiftEC2NodeClass))
	})
	return ret, err
}

// Get retrieves the OpenshiftEC2NodeClass from the indexer for a given namespace and name.
func (s openshiftEC2NodeClassNamespaceLister) Get(name string) (*v1beta1.OpenshiftEC2NodeClass, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("openshiftec2nodeclass"), name)
	}
	return obj.(*v1beta1.OpenshiftEC2NodeClass), nil
}
