package config

import (
    "os"
    "testing"
)

func TestLoadConfig(t *testing.T) {
    tests := []struct {
        name    string
        env     map[string]string
        wantErr bool
    }{
        {
            name: "valid minimal config",
            env: map[string]string{
                "AWS_ACCESS_KEY_ID":     "test-key",
                "AWS_SECRET_ACCESS_KEY": "test-secret",
                "S3_BUCKET":             "test-bucket",
                "REPOSITORY":            "owner/repo",
            },
            wantErr: false,
        },
        {
            name: "missing required field",
            env: map[string]string{
                "AWS_ACCESS_KEY_ID": "test-key",
                // Missing AWS_SECRET_ACCESS_KEY
                "S3_BUCKET":  "test-bucket",
                "REPOSITORY": "owner/repo",
            },
            wantErr: true,
        },
        {
            name: "invalid repository format",
            env: map[string]string{
                "AWS_ACCESS_KEY_ID":     "test-key",
                "AWS_SECRET_ACCESS_KEY": "test-secret",
                "S3_BUCKET":             "test-bucket",
                "REPOSITORY":            "invalid-repo", // No slash
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Clear environment
            os.Clearenv()
            
            // Set test environment
            for k, v := range tt.env {
                os.Setenv(k, v)
            }
            
            cfg, err := LoadConfig()
            
            if (err != nil) != tt.wantErr {
                t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if !tt.wantErr && cfg == nil {
                t.Error("LoadConfig() returned nil config")
            }
        })
    }
}

func TestConfigValidate(t *testing.T) {
    tests := []struct {
        name    string
        config  *Config
        wantErr bool
    }{
        {
            name: "valid github config",
            config: &Config{
                AWSAccessKeyID:     "key",
                AWSSecretAccessKey: "secret",
                S3Bucket:           "bucket",
                Repository:         "owner/repo",
                SBOMSource:         "github",
            },
            wantErr: false,
        },
        {
            name: "valid mend config",
            config: &Config{
                AWSAccessKeyID:     "key",
                AWSSecretAccessKey: "secret",
                S3Bucket:           "bucket",
                SBOMSource:         "mend",
                MendEmail:          "test@example.com",
                MendOrgUUID:        "123e4567-e89b-12d3-a456-426614174000",
                MendUserKey:        "user-key",
                MendProjectUUID:    "123e4567-e89b-12d3-a456-426614174001",
            },
            wantErr: false,
        },
        {
            name: "invalid mend config - missing email",
            config: &Config{
                AWSAccessKeyID:     "key",
                AWSSecretAccessKey: "secret",
                S3Bucket:           "bucket",
                SBOMSource:         "mend",
                // Missing MendEmail
                MendOrgUUID:     "123e4567-e89b-12d3-a456-426614174000",
                MendUserKey:     "user-key",
                MendProjectUUID: "123e4567-e89b-12d3-a456-426614174001",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.config.Validate()
            if (err != nil) != tt.wantErr {
                t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
