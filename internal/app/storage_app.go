package app

import (
	"sso/internal/storage/sqlite"
)

type StorageApp struct {
	storage *sqlite.Storage
}

func NewStorageApp(storagePath string) (*StorageApp, error) {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		return nil, err
	}
	return &StorageApp{storage: storage}, nil
}

func (s *StorageApp) Stop() error {
	return s.storage.Close()
}

func (s *StorageApp) Storage() *sqlite.Storage {
	return s.storage
}
