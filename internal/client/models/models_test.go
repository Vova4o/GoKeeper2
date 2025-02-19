package models

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestDataContentImplementations(t *testing.T) {
    var _ DataContent = LoginPassword{}
    var _ DataContent = TextNote{}
    var _ DataContent = BinaryData{}
    var _ DataContent = BankCard{}
}

func TestDataInitialization(t *testing.T) {
    loginPassword := LoginPassword{
        DBID:     1,
        Title:    "test title",
        Login:    "test login",
        Password: "test password",
    }

    data := Data{
        DBID:     1,
        DataType: DataTypeLoginPassword,
        Data:     loginPassword,
    }

    assert.Equal(t, 1, data.DBID)
    assert.Equal(t, DataTypeLoginPassword, data.DataType)
    assert.Equal(t, loginPassword, data.Data)
}

func TestDataToPassInitialization(t *testing.T) {
    dataToPass := DataToPass{
        DBID:       1,
        DataType:   DataTypeLoginPassword,
        DataString: "encrypted_data",
    }

    assert.Equal(t, 1, dataToPass.DBID)
    assert.Equal(t, DataTypeLoginPassword, dataToPass.DataType)
    assert.Equal(t, "encrypted_data", dataToPass.DataString)
}