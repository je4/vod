package main

import (
	"emperror.dev/errors"
	"github.com/BurntSushi/toml"
	loaderConfig "github.com/je4/certloader/v2/pkg/loader"
	"github.com/je4/utils/v2/pkg/config"
	"io/fs"
	"os"
)

type VODConfig struct {
	LocalAddr    string               `toml:"localaddr"`
	ExternalAddr string               `toml:"externaladdr"`
	JWTKey       string               `toml:"jwtkey"`
	JWTAlg       []string             `toml:"jwtalg"`
	WebTLS       *loaderConfig.Config `toml:"webtls"`
	CacheTimeout config.Duration      `toml:"cachetimeout"`
	LogFile      string               `toml:"logfile"`
	LogLevel     string               `toml:"loglevel"`
}

func LoadVODConfig(fSys fs.FS, fp string, conf *VODConfig) error {
	if _, err := fs.Stat(fSys, fp); err != nil {
		path, err := os.Getwd()
		if err != nil {
			return errors.Wrap(err, "cannot get current working directory")
		}
		fSys = os.DirFS(path)
		fp = "vod.toml"
	}
	data, err := fs.ReadFile(fSys, fp)
	if err != nil {
		return errors.Wrapf(err, "cannot read file [%v] %s", fSys, fp)
	}
	_, err = toml.Decode(string(data), conf)
	if err != nil {
		return errors.Wrapf(err, "error loading config file %v", fp)
	}
	return nil
}
