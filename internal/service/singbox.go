package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"openwrt-parser-go/internal/openwrt"
)

const MaxSingBoxConfigSize int64 = 1024 * 1024

type SingBoxService struct {
	openwrt *openwrt.Client
}

func NewSingBoxService(client *openwrt.Client) *SingBoxService {
	return &SingBoxService{openwrt: client}
}

func (s *SingBoxService) Status(ctx context.Context) (openwrt.SingBoxStatus, error) {
	return s.openwrt.SingBoxStatus(ctx)
}

func (s *SingBoxService) Install(ctx context.Context, contents []byte) (openwrt.SingBoxStatus, error) {
	if len(contents) == 0 {
		return openwrt.SingBoxStatus{}, errors.New("configuration file is empty")
	}
	if int64(len(contents)) > MaxSingBoxConfigSize {
		return openwrt.SingBoxStatus{}, fmt.Errorf("configuration file exceeds %d bytes", MaxSingBoxConfigSize)
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return openwrt.SingBoxStatus{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if root == nil {
		return openwrt.SingBoxStatus{}, errors.New("sing-box configuration must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return openwrt.SingBoxStatus{}, errors.New("configuration contains more than one JSON value")
		}
		return openwrt.SingBoxStatus{}, fmt.Errorf("invalid JSON: %w", err)
	}

	return s.openwrt.InstallSingBoxConfig(ctx, contents)
}
