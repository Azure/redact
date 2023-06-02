package redact_test

import (
	"strings"
	"testing"

	"github.com/azure/redact"
	"github.com/stretchr/testify/assert"
)

const (
	secretVal    = "thisIsASecret"
	nonSecretVal = "thisIsAStandardVal"
)

var (
	secretPtrVal = "thisIsAPtrSecret"
)

type StringType string

type TestStruct struct {
	Secret           string
	SecretStringType StringType
	SecretPtr        *string
	NonSecret        string `redact:"nonsecret"`
	Interface        interface{}
	unexported       string
	unexportedMap    map[string]string
}

type TestStructList struct {
	Data               []*TestStruct
	StringSliceData    []string
	IntSliceData       []int
	StringPtrSliceData []*string
}

type TestMaps struct {
	Secrets           map[string]string
	SecretPtrs        map[string]*string
	TestStructSecrets map[string]*TestStruct
}

type TestMapList struct {
	Data []*TestMaps
}

type TestNestedStruct struct {
	TestStruct    TestStruct
	TestStructPtr *TestStruct
}

func TestStringTestStruct(t *testing.T) {
	t.Run("Basic Secret Redaction", func(t *testing.T) {
		newTestStruct := func() *TestStruct {
			return &TestStruct{
				NonSecret:        nonSecretVal,
				Secret:           secretVal,
				SecretStringType: secretVal,
				SecretPtr:        &secretPtrVal,
				unexported:       nonSecretVal,
				unexportedMap:    map[string]string{"": ""},
			}
		}

		validate := func(tStruct *TestStruct) {
			assert.Equal(t, nonSecretVal, tStruct.NonSecret, "should contain non secret value")
			assert.Equal(t, redact.RedactStrConst, tStruct.Secret, "should redact secret value")
			assert.Equal(t, StringType(redact.RedactStrConst), tStruct.SecretStringType, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *tStruct.SecretPtr, "should redact secret value")
			assert.Equal(t, nonSecretVal, tStruct.unexported, "should contain non secret value")
		}

		tStruct := newTestStruct()
		err := redact.Redact(tStruct)
		assert.NoError(t, err, "should not fail to redact struct")
		validate(tStruct)

		tStruct = newTestStruct()
		tStructCopy := redact.AsCopy(tStruct)
		assert.Equal(t, newTestStruct(), tStruct)
		validate(tStructCopy)
		redact.ValidateNoExportedAliases(tStruct, tStructCopy)
	})

	t.Run("Should still redact empty strings", func(t *testing.T) {
		newTestStruct := func() *TestStruct {
			emptyStrVal := ""

			return &TestStruct{
				NonSecret: nonSecretVal,
				Secret:    "",
				SecretPtr: &emptyStrVal,
			}
		}

		validate := func(tStruct *TestStruct) {
			assert.Equal(t, nonSecretVal, tStruct.NonSecret, "should contain non secret value")
			assert.Equal(t, redact.RedactStrConst, tStruct.Secret, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *tStruct.SecretPtr, "should redact secret value")
		}

		tStruct := newTestStruct()
		err := redact.Redact(tStruct)
		assert.NoError(t, err, "should not fail to redact struct")
		validate(tStruct)

		tStruct = newTestStruct()
		tStructCopy := redact.AsCopy(tStruct)
		assert.Equal(t, newTestStruct(), tStruct)
		validate(tStructCopy)
		redact.ValidateNoExportedAliases(tStruct, tStructCopy)
	})
}

func TestStringTestStructList(t *testing.T) {
	t.Run("Basic Secret Redaction", func(t *testing.T) {
		newTestStructList := func() *TestStructList {
			tStruct := &TestStruct{
				NonSecret: nonSecretVal,
				Secret:    secretVal,
				SecretPtr: &secretPtrVal,
			}

			return &TestStructList{
				Data:               []*TestStruct{tStruct},
				StringSliceData:    []string{secretVal},
				IntSliceData:       []int{0},
				StringPtrSliceData: []*string{&secretPtrVal, nil},
			}
		}

		validate := func(list *TestStructList) {
			assert.Equal(t, nonSecretVal, list.Data[0].NonSecret, "should contain non secret value")
			assert.Equal(t, redact.RedactStrConst, list.Data[0].Secret, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *list.Data[0].SecretPtr, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, list.StringSliceData[0], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *list.StringPtrSliceData[0], "should redact secret value")
		}

		list := newTestStructList()
		err := redact.Redact(list)
		assert.NoError(t, err, "should not fail to redact struct")
		validate(list)

		list = newTestStructList()
		listCopy := redact.AsCopy(list)
		assert.Equal(t, newTestStructList(), list)
		validate(listCopy)
		redact.ValidateNoExportedAliases(list, listCopy)
	})

	t.Run("Should still redact empty strings", func(t *testing.T) {
		newTestStructList := func() *TestStructList {
			emptyStrVal := ""

			tStruct := &TestStruct{
				NonSecret: nonSecretVal,
				Secret:    "",
				SecretPtr: &emptyStrVal,
			}

			return &TestStructList{
				Data:               []*TestStruct{tStruct},
				StringSliceData:    []string{""},
				IntSliceData:       []int{0},
				StringPtrSliceData: []*string{&[]string{""}[0], nil},
			}
		}

		validate := func(list *TestStructList) {
			assert.Equal(t, nonSecretVal, list.Data[0].NonSecret, "should contain non secret value")
			assert.Equal(t, redact.RedactStrConst, list.Data[0].Secret, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *list.Data[0].SecretPtr, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, list.StringSliceData[0], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *list.StringPtrSliceData[0], "should redact secret value")
		}

		list := newTestStructList()
		err := redact.Redact(list)
		assert.NoError(t, err, "should not fail to redact struct")
		validate(list)

		list = newTestStructList()
		listCopy := redact.AsCopy(list)
		assert.Equal(t, newTestStructList(), list)
		validate(listCopy)
		redact.ValidateNoExportedAliases(list, listCopy)
	})
}

func TestStringTestMapAndEmbedded(t *testing.T) {
	t.Run("Should Redact Map And Slice Structs", func(t *testing.T) {
		newTestMaps := func() *TestMaps {
			return &TestMaps{
				Secrets: map[string]string{
					"secret-key-old": secretVal,
					"secret-key-new": secretVal,
				},
				SecretPtrs: map[string]*string{
					"ptr-secret-key": &secretPtrVal,
				},
				TestStructSecrets: map[string]*TestStruct{
					"ptr-test-struct-key": {
						NonSecret: nonSecretVal,
						Secret:    secretVal,
						SecretPtr: &secretPtrVal,
					},
				},
			}
		}

		validate := func(tMaps *TestMaps) {
			assert.Equal(t, redact.RedactStrConst, tMaps.Secrets["secret-key-old"], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, tMaps.Secrets["secret-key-new"], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *tMaps.SecretPtrs["ptr-secret-key"], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, tMaps.TestStructSecrets["ptr-test-struct-key"].Secret, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *tMaps.TestStructSecrets["ptr-test-struct-key"].SecretPtr, "should redact secret value")
			assert.Equal(t, nonSecretVal, tMaps.TestStructSecrets["ptr-test-struct-key"].NonSecret, "should redact secret value")
		}

		tMaps := newTestMaps()
		err := redact.Redact(tMaps)
		assert.NoError(t, err, "should not fail to redact struct")
		validate(tMaps)

		tMaps = newTestMaps()
		tMapsCopy := redact.AsCopy(tMaps)
		assert.Equal(t, newTestMaps(), tMaps)
		validate(tMapsCopy)
		redact.ValidateNoExportedAliases(tMaps, tMapsCopy)
	})

	t.Run("Should Redact Map And Slice Structs", func(t *testing.T) {
		newTestMapList := func() *TestMapList {
			tMaps := &TestMaps{
				Secrets: map[string]string{
					"secret-key-old": secretVal,
					"secret-key-new": secretVal,
				},
				SecretPtrs: map[string]*string{
					"ptr-secret-key": &secretPtrVal,
				},
				TestStructSecrets: map[string]*TestStruct{
					"ptr-test-struct-key": {
						NonSecret: nonSecretVal,
						Secret:    secretVal,
						SecretPtr: &secretPtrVal,
					},
				},
			}

			return &TestMapList{
				Data: []*TestMaps{tMaps},
			}
		}

		validate := func(testMapList *TestMapList) {
			assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].Secrets["secret-key-old"], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].Secrets["secret-key-new"], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *testMapList.Data[0].SecretPtrs["ptr-secret-key"], "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].TestStructSecrets["ptr-test-struct-key"].Secret, "should redact secret value")
			assert.Equal(t, redact.RedactStrConst, *testMapList.Data[0].TestStructSecrets["ptr-test-struct-key"].SecretPtr, "should redact secret value")
			assert.Equal(t, nonSecretVal, testMapList.Data[0].TestStructSecrets["ptr-test-struct-key"].NonSecret, "should redact secret value")
		}

		testMapList := newTestMapList()
		err := redact.Redact(testMapList)
		assert.NoError(t, err, "should not fail to redact struct")
		validate(testMapList)

		testMapList = newTestMapList()
		testMapListCopy := redact.AsCopy(testMapList)
		assert.Equal(t, newTestMapList(), testMapList)
		validate(testMapListCopy)
		redact.ValidateNoExportedAliases(testMapList, testMapListCopy)
	})
}

func TestNotSettable(t *testing.T) {
	err := redact.Redact(1)
	assert.Error(t, err)

	// test does not apply for redact.AsCopy()
}

func TestInterface(t *testing.T) {
	newInterface := func() interface{} {
		return interface{}(&TestStruct{})
	}

	validate := func(i interface{}) {
		assert.Equal(t, i, &TestStruct{Secret: redact.RedactStrConst, SecretStringType: redact.RedactStrConst})
	}

	i := newInterface()
	err := redact.Redact(&i)
	assert.NoError(t, err)
	validate(i)

	i = newInterface()
	iCopy := redact.AsCopy(i)
	assert.Equal(t, newInterface(), i)
	validate(iCopy)
	redact.ValidateNoExportedAliases(i, iCopy)
}

func TestNestedInterface(t *testing.T) {
	newTestStruct := func() *TestStruct {
		return &TestStruct{
			Interface: &TestStruct{},
		}
	}

	validate := func(tStruct *TestStruct) {
		assert.Equal(t, tStruct, &TestStruct{
			Secret:           redact.RedactStrConst,
			SecretStringType: redact.RedactStrConst,
			Interface: &TestStruct{
				Secret:           redact.RedactStrConst,
				SecretStringType: redact.RedactStrConst,
			},
		})
	}

	tStruct := newTestStruct()
	err := redact.Redact(&tStruct)
	assert.NoError(t, err)
	validate(tStruct)

	tStruct = newTestStruct()
	tStructCopy := redact.AsCopy(tStruct)
	assert.Equal(t, newTestStruct(), tStruct)
	validate(tStructCopy)
	redact.ValidateNoExportedAliases(tStruct, tStructCopy)
}

func TestNestedStructs(t *testing.T) {
	newTestNestedStruct := func() *TestNestedStruct {
		return &TestNestedStruct{
			TestStructPtr: &TestStruct{SecretPtr: &[]string{""}[0]},
		}
	}

	validate := func(tns *TestNestedStruct) {
		assert.Equal(t, tns, &TestNestedStruct{
			TestStruct:    TestStruct{Secret: redact.RedactStrConst, SecretStringType: redact.RedactStrConst, SecretPtr: nil},
			TestStructPtr: &TestStruct{Secret: redact.RedactStrConst, SecretStringType: redact.RedactStrConst, SecretPtr: &[]string{redact.RedactStrConst}[0]},
		})
	}

	tns := newTestNestedStruct()
	err := redact.Redact(tns)
	assert.NoError(t, err)
	validate(tns)

	tns = newTestNestedStruct()
	tnsCopy := redact.AsCopy(tns)
	assert.Equal(t, newTestNestedStruct(), tns)
	validate(tnsCopy)
	redact.ValidateNoExportedAliases(tns, tnsCopy)
}

func TestCustomRedactor(t *testing.T) {
	type SStruct struct {
		S string `redact:"lower"`
	}

	newSStruct := func() *SStruct {
		return &SStruct{"DATA"}
	}

	validate := func(s *SStruct) {
		assert.Equal(t, s.S, "data")
	}

	s := newSStruct()
	redact.AddRedactor("lower", strings.ToLower)
	err := redact.Redact(s)
	assert.NoError(t, err)
	validate(s)

	s = newSStruct()
	sCopy := redact.AsCopy(s)
	assert.Equal(t, newSStruct(), s)
	validate(sCopy)
	redact.ValidateNoExportedAliases(s, sCopy)
}

func TestArray(t *testing.T) {
	type AStruct struct {
		SecretStrings    [2]string
		NotSecretStrings [2]string `redact:"nonsecret"`
	}

	newAStruct := func() *AStruct {
		return &AStruct{}
	}

	validate := func(tStruct *AStruct) {
		assert.Equal(t, "", tStruct.NotSecretStrings[0], "should contain non secret value")
		assert.Equal(t, "", tStruct.NotSecretStrings[1], "should contain non secret value")
		assert.Equal(t, redact.RedactStrConst, tStruct.SecretStrings[0], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, tStruct.SecretStrings[1], "should redact secret value")

	}

	tStruct := newAStruct()
	err := redact.Redact(tStruct)
	assert.NoError(t, err, "should not fail to redact struct")
	validate(tStruct)

	tStruct = newAStruct()
	tStructCopy := redact.AsCopy(tStruct)
	assert.Equal(t, newAStruct(), tStruct)
	validate(tStructCopy)
	redact.ValidateNoExportedAliases(tStruct, tStructCopy)
}
