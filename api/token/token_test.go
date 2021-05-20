// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	// "encoding/base64"
	"errors"
	"hash"
	"time"

	. "github.com/globocom/huskyCI/api/token"
	"github.com/globocom/huskyCI/api/types"
)

type FakeExternal struct {
	expectedURL               string
	expectedValidateError     error
	expectedToken             string
	expectedGenerateError     error
	expectedTime              time.Time
	expectedStoreAccessError  error
	expectedAccessToken       types.DBToken
	expectedFindAccessError   error
	expectedFindRepoError     error
	expectedUuid              string
	expectedDecodedString     string
	expectedDecodeToError     error
	expectedUpdateAccessError error
	returnedAccessToken       types.DBToken
}

type FakeHashGen struct {
	expectedSalt              string
	expectedGenerateSaltError error
	expectedDecodedSalt       []byte
	expectedDecodeSaltError   error
	expectedHashName          string
	expectedKeyLength         int
	expectedIterations        int
	expectedHashValue         string
}

func (fE *FakeExternal) ValidateURL(url string) (string, error) {
	return fE.expectedURL, fE.expectedValidateError
}

func (fE *FakeExternal) GenerateToken() (string, error) {
	return fE.expectedToken, fE.expectedGenerateError
}

func (fE *FakeExternal) GetTimeNow() time.Time {
	return fE.expectedTime
}

func (fE *FakeExternal) StoreAccessToken(accessToken types.DBToken) error {
	return fE.expectedStoreAccessError
}

func (fE *FakeExternal) FindAccessToken(id string) (types.DBToken, error) {
	return fE.expectedAccessToken, fE.expectedFindAccessError
}

func (fE *FakeExternal) FindRepoURL(repositoryURL string) error {
	return fE.expectedFindRepoError
}

func (fE *FakeExternal) GenerateUUID() string {
	return fE.expectedUuid
}

func (fE *FakeExternal) EncodeBase64(m string) string {
	return m
}

func (fE *FakeExternal) DecodeToStringBase64(encodedVal string) (string, error) {
	return fE.expectedDecodedString, fE.expectedDecodeToError
}

func (fH *FakeExternal) UpdateAccessToken(id string, accesstoken types.DBToken) error {
	fH.returnedAccessToken = accesstoken
	return fH.expectedUpdateAccessError
}

func (fH *FakeHashGen) GenerateSalt() (string, error) {
	return fH.expectedSalt, fH.expectedGenerateSaltError
}

func (fH *FakeHashGen) DecodeSaltValue(salt string) ([]byte, error) {
	return fH.expectedDecodedSalt, fH.expectedDecodeSaltError
}

func (fH *FakeHashGen) GetHashName() string {
	return fH.expectedHashName
}

func (fH *FakeHashGen) GetKeyLength() int {
	return fH.expectedKeyLength
}

func (fH *FakeHashGen) GetIterations() int {
	return fH.expectedIterations
}

func (fH *FakeHashGen) GenHashValue(value, salt []byte, iter, keyLen int, hashFunc func() hash.Hash) string {
	return fH.expectedHashValue
}

func (fH *FakeHashGen) GetCredsFromDB(username string) (types.User, error) {
	return types.User{}, nil
}

var _ = Describe("Token", func() {
	Context("When URL validation returns an error", func() {
		It("Should return the same error and an empty string", func() {
			fakeExt := FakeExternal{
				expectedURL:           "",
				expectedValidateError: errors.New("URL is not valid"),
			}
			tokenGen := THandler{
				External: &fakeExt,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(errors.New("URL is not valid")))
		})
	})
	Context("When validatedURL is empty", func() {
		It("Should return the expected error and an empty string", func() {
			fakeExt := FakeExternal{
				expectedURL:           "",
				expectedValidateError: nil,
			}
			tokenGen := THandler{
				External: &fakeExt,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(errors.New("Empty URL is not valid")))
		})
	})
	Context("When GenerateToken returns an error", func() {
		It("Should return the same error and an empty string", func() {
			fakeExt := FakeExternal{
				expectedURL:           "MyValidURL",
				expectedValidateError: nil,
				expectedToken:         "",
				expectedGenerateError: errors.New("Failed to generate token"),
			}
			tokenGen := THandler{
				External: &fakeExt,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(errors.New("Failed to generate token")))
		})
	})
	Context("When GenerateSalt returns an error", func() {
		It("Should return the same error and an empty string", func() {
			fakeExt := FakeExternal{
				expectedURL:           "MyValidURL",
				expectedValidateError: nil,
				expectedToken:         "MyBrandNewToken",
				expectedGenerateError: nil,
			}
			fakeHash := FakeHashGen{
				expectedSalt:              "",
				expectedGenerateSaltError: errors.New("Could not generate a valid salt"),
			}
			tokenGen := THandler{
				External: &fakeExt,
				HashGen:  &fakeHash,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(fakeHash.expectedGenerateSaltError))
		})
	})
	Context("When DecodeSalt returns an error", func() {
		It("Should return the same error and an empty string", func() {
			fakeExt := FakeExternal{
				expectedURL:           "MyValidURL",
				expectedValidateError: nil,
				expectedToken:         "MyBrandNewToken",
				expectedGenerateError: nil,
			}
			fakeHash := FakeHashGen{
				expectedSalt:              "MySalt",
				expectedGenerateSaltError: nil,
				expectedDecodedSalt:       make([]byte, 0),
				expectedDecodeSaltError:   errors.New("Failed to decode salt value"),
			}
			tokenGen := THandler{
				External: &fakeExt,
				HashGen:  &fakeHash,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(fakeHash.expectedDecodeSaltError))
		})
	})
	Context("When GetValidHashFunction returns a false boolean", func() {
		It("Should return the expected error", func() {
			fakeExt := FakeExternal{
				expectedURL:           "MyValidURL",
				expectedValidateError: nil,
				expectedToken:         "MyBrandNewToken",
				expectedGenerateError: nil,
			}
			fakeHash := FakeHashGen{
				expectedSalt:              "MySalt",
				expectedGenerateSaltError: nil,
				expectedDecodedSalt:       make([]byte, 0),
				expectedDecodeSaltError:   nil,
				expectedHashName:          "",
				expectedKeyLength:         32,
				expectedIterations:        1024,
			}
			tokenGen := THandler{
				External: &fakeExt,
				HashGen:  &fakeHash,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(errors.New("Invalid hash function")))
		})
	})
	Context("When StoreAccessToken returns an error", func() {
		It("Should return the same error and an empty string", func() {
			fakeExt := FakeExternal{
				expectedURL:              "MyValidURL",
				expectedValidateError:    nil,
				expectedToken:            "MyBrandNewToken",
				expectedGenerateError:    nil,
				expectedTime:             time.Now(),
				expectedUuid:             "MuUUidValue",
				expectedStoreAccessError: errors.New("Failed to store token"),
			}
			fakeHash := FakeHashGen{
				expectedSalt:              "MySalt",
				expectedGenerateSaltError: nil,
				expectedDecodedSalt:       make([]byte, 0),
				expectedDecodeSaltError:   nil,
				expectedHashName:          "Sha512",
				expectedKeyLength:         32,
				expectedIterations:        1024,
				expectedHashValue:         "MyTokenHashValue",
			}
			tokenGen := THandler{
				External: &fakeExt,
				HashGen:  &fakeHash,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal(""))
			Expect(err).To(Equal(fakeExt.expectedStoreAccessError))
		})
	})
	Context("When a valid token is generated", func() {
		It("Should return the expected string and a nil error", func() {
			fakeExt := FakeExternal{
				expectedURL:              "MyValidURL",
				expectedValidateError:    nil,
				expectedToken:            "MyBrandNewToken",
				expectedGenerateError:    nil,
				expectedTime:             time.Now(),
				expectedUuid:             "MyUUidValue",
				expectedStoreAccessError: nil,
			}
			fakeHash := FakeHashGen{
				expectedSalt:              "MySalt",
				expectedGenerateSaltError: nil,
				expectedDecodedSalt:       make([]byte, 0),
				expectedDecodeSaltError:   nil,
				expectedHashName:          "Sha512",
				expectedKeyLength:         32,
				expectedIterations:        1024,
				expectedHashValue:         "MyTokenHashValue",
			}
			tokenGen := THandler{
				External: &fakeExt,
				HashGen:  &fakeHash,
			}
			accessToken, err := tokenGen.GenerateAccessToken(types.TokenRequest{
				RepositoryURL: "myRepo.com",
			})
			Expect(accessToken).To(Equal("MyUUidValue:MyBrandNewToken"))
			Expect(err).To(BeNil())
		})
	})
	Describe("GetSplitted", func() {
		Context("When DecodeToStringBase64 returns an error", func() {
			It("Should return the same error as expected and nil returned strings", func() {
				fakeExt := FakeExternal{
					expectedDecodedString: "",
					expectedDecodeToError: errors.New("Failed to decode to base64"),
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				UUid, Random, err := tokenVal.GetSplitted("MyTokenBase64")
				Expect(UUid).To(Equal(""))
				Expect(Random).To(Equal(""))
				Expect(err).To(Equal(fakeExt.expectedDecodeToError))
			})
		})
		Context("When DecodeToStringBase64 returns an invalid access token format", func() {
			It("Should return the expected error and nil returned strings", func() {
				fakeExt := FakeExternal{
					expectedDecodedString: "InvalidTokenFormat",
					expectedDecodeToError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				UUid, Random, err := tokenVal.GetSplitted("MyTokenBase64")
				Expect(UUid).To(Equal(""))
				Expect(Random).To(Equal(""))
				Expect(err).To(Equal(errors.New("Invalid access token format")))
			})
		})
		Context("When a valid access token is passed and a decoded base64 is returned", func() {
			It("Should return the expected UUID and Random data, and a nil error ", func() {
				fakeExt := FakeExternal{
					expectedDecodedString: "MyUUID:MyRandomData",
					expectedDecodeToError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				UUid, Random, err := tokenVal.GetSplitted("MyTokenBase64")
				Expect(UUid).To(Equal("MyUUID"))
				Expect(Random).To(Equal("MyRandomData"))
				Expect(err).To(BeNil())
			})
		})
	})
	Describe("ValidateRandomData", func() {
		Context("When DecodeSaltValue returns an error", func() {
			It("Should return the same error", func() {
				hashGen := FakeHashGen{
					expectedDecodedSalt:     make([]byte, 0),
					expectedDecodeSaltError: errors.New("Could not return the decoded value"),
				}
				tokenVal := THandler{
					HashGen: &hashGen,
				}
				Expect(tokenVal.ValidateRandomData("ReceivedRandom", "StoredRandom", "StoredSalt")).To(Equal(hashGen.expectedDecodeSaltError))
			})
		})
		Context("When GetValidHashFunction returns a false boolean", func() {
			It("Should return the expected error", func() {
				hashGen := FakeHashGen{
					expectedDecodedSalt:     []byte("StoredSalt"),
					expectedDecodeSaltError: nil,
					expectedHashName:        "InvalidSha",
				}
				tokenVal := THandler{
					HashGen: &hashGen,
				}
				Expect(tokenVal.ValidateRandomData("ReceivedRandom", "StoredRandom", "StoredSalt")).To(Equal(errors.New("Invalid hash function")))
			})
		})
		Context("When calculated hash differs from the stored hash", func() {
			It("Should return the expected error", func() {
				hashGen := FakeHashGen{
					expectedDecodedSalt:     []byte("StoredSalt"),
					expectedDecodeSaltError: nil,
					expectedHashName:        "Sha512",
					expectedKeyLength:       128,
					expectedIterations:      1024,
					expectedHashValue:       "DifferentFromTheStored",
				}
				tokenVal := THandler{
					HashGen: &hashGen,
				}
				Expect(tokenVal.ValidateRandomData("ReceivedRandom", "StoredRandom", "StoredSalt")).To(Equal(errors.New("Hash value from random data is different")))
			})
		})
		Context("When calculated hash is equal from the stored hash", func() {
			It("Should return a nil error", func() {
				hashGen := FakeHashGen{
					expectedDecodedSalt:     []byte("StoredSalt"),
					expectedDecodeSaltError: nil,
					expectedHashName:        "Sha512",
					expectedKeyLength:       128,
					expectedIterations:      1024,
					expectedHashValue:       "StoredRandomHash",
				}
				tokenVal := THandler{
					HashGen: &hashGen,
				}
				Expect(tokenVal.ValidateRandomData("ReceivedRandom", "StoredRandomHash", "StoredSalt")).To(BeNil())
			})
		})
	})
	Describe("ValidateToken", func() {
		Context("When ValidateURL returns an error", func() {
			It("Should return the same error", func() {
				fakeExt := FakeExternal{
					expectedURL:           "",
					expectedValidateError: errors.New("Invalid URL format"),
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				Expect(tokenVal.ValidateToken("RcvToken", "RcvRepo")).To(Equal(fakeExt.expectedValidateError))
			})
		})
		Context("When GetSplitted returns an error", func() {
			It("Should return the same error", func() {
				fakeExt := FakeExternal{
					expectedURL:           "ValidURLRepo",
					expectedValidateError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				Expect(tokenVal.ValidateToken("InvalidRcvToken", "RcvRepo")).To(Equal(errors.New("Invalid access token format")))
			})
		})
		Context("When FindAccessToken returns an error", func() {
			It("Should return the same error", func() {
				fakeExt := FakeExternal{
					expectedURL:             "ValidURLRepo",
					expectedValidateError:   nil,
					expectedFindAccessError: errors.New("Could not find access token for the given UUID"),
					expectedAccessToken:     types.DBToken{},
					expectedDecodedString:   "UUID:RandomVal",
					expectedDecodeToError:   nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				Expect(tokenVal.ValidateToken("EncodedRcvToken", "RcvRepo")).To(Equal(fakeExt.expectedFindAccessError))
			})
		})
		Context("When access token from DB is not valid", func() {
			It("Should return the expected error", func() {
				fakeExt := FakeExternal{
					expectedURL:             "ValidURLRepo",
					expectedValidateError:   nil,
					expectedFindAccessError: nil,
					expectedAccessToken: types.DBToken{
						IsValid:    false,
						HuskyToken: "StoredHash",
					},
					expectedDecodedString: "UUID:RandomVal",
					expectedDecodeToError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				Expect(tokenVal.ValidateToken("EncodedRcvToken", "RcvRepo")).To(Equal(errors.New("Access token is invalid")))
			})
		})
		Context("When URL stored in DB is different from the received URL", func() {
			It("Should return the expected error", func() {
				fakeExt := FakeExternal{
					expectedURL:             "MyRcvURL",
					expectedValidateError:   nil,
					expectedFindAccessError: nil,
					expectedAccessToken: types.DBToken{
						IsValid:    true,
						HuskyToken: "StoredHash",
						URL:        "MyValidURL",
					},
					expectedDecodedString: "UUID:RandomVal",
					expectedDecodeToError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
				}
				Expect(tokenVal.ValidateToken("EncodedRcvToken", "RcvRepo")).To(Equal(errors.New("Access token doesn't have permission to run analysis in the provided repository")))
			})
		})
		Context("When hash of random data is different from the stored hash", func() {
			It("Should return the expected error from ValidateRandomData", func() {
				fakeHash := FakeHashGen{
					expectedDecodedSalt:     []byte("MySaltDecoded"),
					expectedDecodeSaltError: nil,
					expectedHashName:        "Sha512",
					expectedKeyLength:       256,
					expectedHashValue:       "MyDifferentHash",
				}
				fakeExt := FakeExternal{
					expectedURL:             "MyValidURL",
					expectedValidateError:   nil,
					expectedFindAccessError: nil,
					expectedAccessToken: types.DBToken{
						IsValid:    true,
						HuskyToken: "StoredHash",
						URL:        "MyValidURL",
						Salt:       "MySalt",
					},
					expectedDecodedString: "UUID:RandomVal",
					expectedDecodeToError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
					HashGen:  &fakeHash,
				}
				Expect(tokenVal.ValidateToken("EncodedRcvToken", "RcvRepo")).To(Equal(errors.New("Hash value from random data is different")))
			})
		})
		Context("When hash of random data if equal from the stored hash", func() {
			It("Should return the expected error from ValidateRandomData", func() {
				fakeHash := FakeHashGen{
					expectedDecodedSalt:     []byte("MySaltDecoded"),
					expectedDecodeSaltError: nil,
					expectedHashName:        "Sha512",
					expectedKeyLength:       256,
					expectedHashValue:       "MyValidHash",
				}
				fakeExt := FakeExternal{
					expectedURL:             "MyValidURL",
					expectedValidateError:   nil,
					expectedFindAccessError: nil,
					expectedAccessToken: types.DBToken{
						IsValid:    true,
						HuskyToken: "MyValidHash",
						URL:        "MyValidURL",
						Salt:       "MySalt",
					},
					expectedDecodedString: "UUID:RandomVal",
					expectedDecodeToError: nil,
				}
				tokenVal := THandler{
					External: &fakeExt,
					HashGen:  &fakeHash,
				}
				Expect(tokenVal.ValidateToken("EncodedRcvToken", "RcvRepo")).To(BeNil())
			})
		})
	})
	Describe("VerifyRepo", func() {
		Context("When ValidateURL returns an error", func() {
			It("Should return the same error", func() {
				fakeExt := FakeExternal{
					expectedURL:           "",
					expectedValidateError: errors.New("Repository does not have a valid format"),
				}
				verRepo := THandler{
					External: &fakeExt,
				}
				Expect(verRepo.VerifyRepo("MyRepo")).To(Equal(fakeExt.expectedValidateError))
			})
		})
		Context("When FindRepoURL returns something", func() {
			It("Should return the same error if it has returned an error", func() {
				fakeExt := FakeExternal{
					expectedURL:           "https://www.github.com/myProject",
					expectedValidateError: nil,
					expectedFindRepoError: errors.New("Repository URL not found"),
				}
				verRepo := THandler{
					External: &fakeExt,
				}
				Expect(verRepo.VerifyRepo("MyRepo")).To(Equal(fakeExt.expectedFindRepoError))
			})
			It("Should return nil if the a repository URL was found", func() {
				fakeExt := FakeExternal{
					expectedURL:           "https://www.github.com/myProject",
					expectedValidateError: nil,
					expectedFindRepoError: nil,
				}
				verRepo := THandler{
					External: &fakeExt,
				}
				Expect(verRepo.VerifyRepo("MyRepo")).To(BeNil())
			})
		})
	})
	Describe("InvalidateToken", func() {
		Context("When GetSplitted returns an error", func() {
			It("Should return the same error", func() {
				fakeExt := FakeExternal{
					expectedDecodedString: "InvalidTokenFormat",
					expectedDecodeToError: nil,
				}
				invalToken := THandler{
					External: &fakeExt,
				}
				Expect(invalToken.InvalidateToken("RcvToken")).To(Equal(errors.New("Invalid access token format")))
			})
		})
		Context("When FindAccessToken returns an error", func() {
			It("Should return the same error", func() {
				fakeExt := FakeExternal{
					expectedDecodedString:   "MyUUID:MyRandom",
					expectedDecodeToError:   nil,
					expectedFindAccessError: errors.New("Could not find access token in DB"),
					expectedAccessToken:     types.DBToken{},
				}
				invalToken := THandler{
					External: &fakeExt,
				}
				Expect(invalToken.InvalidateToken("RcvToken")).To(Equal(fakeExt.expectedFindAccessError))
			})
		})
		Context("When FindAccessToken returns a valid access token", func() {
			It("Should update entry in DB is false boolean in IsValid parameter", func() {
				fakeExt := FakeExternal{
					expectedDecodedString:   "MyUUID:MyRandom",
					expectedDecodeToError:   nil,
					expectedFindAccessError: nil,
					expectedAccessToken: types.DBToken{
						IsValid:    true,
						HuskyToken: "StoredEncodedRandomData",
						UUID:       "MyUUID",
						URL:        "MyURL",
						Salt:       "MySalt",
					},
					expectedUpdateAccessError: nil,
				}
				invalToken := THandler{
					External: &fakeExt,
				}
				err := invalToken.InvalidateToken("RcvToken")
				Expect(err).To(BeNil())
				Expect(fakeExt.returnedAccessToken.HuskyToken).To(Equal(fakeExt.expectedAccessToken.HuskyToken))
				Expect(fakeExt.returnedAccessToken.UUID).To(Equal(fakeExt.expectedAccessToken.UUID))
				Expect(fakeExt.returnedAccessToken.URL).To(Equal(fakeExt.expectedAccessToken.URL))
				Expect(fakeExt.returnedAccessToken.Salt).To(Equal(fakeExt.expectedAccessToken.Salt))
				Expect(fakeExt.returnedAccessToken.IsValid).To(BeFalse())
			})
		})
	})
})
