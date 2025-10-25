package validation

import (
    "testing"
)

func TestSanitizeRepository(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {
            name:    "valid repository",
            input:   "owner/repo",
            want:    "owner/repo",
            wantErr: false,
        },
        {
            name:    "repository with hyphens",
            input:   "my-org/my-repo",
            want:    "my-org/my-repo",
            wantErr: false,
        },
        {
            name:    "repository with dots",
            input:   "my.org/repo.name",
            want:    "my.org/repo.name",
            wantErr: false,
        },
        {
            name:    "removes dangerous characters",
            input:   "owner$bad/repo;rm",
            want:    "ownerbad/reporm",
            wantErr: false,
        },
        {
            name:    "invalid - no slash",
            input:   "invalidrepo",
            want:    "",
            wantErr: true,
        },
        {
            name:    "invalid - empty owner",
            input:   "/repo",
            want:    "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := SanitizeRepository(tt.input)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("SanitizeRepository() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if got != tt.want {
                t.Errorf("SanitizeRepository() = %v, want %v", got, tt.want)
            }
        })
    }
}

func TestSanitizeEmail(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {
            name:    "valid email",
            input:   "user@example.com",
            want:    "user@example.com",
            wantErr: false,
        },
        {
            name:    "email with plus",
            input:   "user+tag@example.com",
            want:    "user+tag@example.com",
            wantErr: false,
        },
        {
            name:    "removes newlines",
            input:   "user@example.com\n",
            want:    "user@example.com",
            wantErr: false,
        },
        {
            name:    "invalid - no @",
            input:   "invalid-email",
            want:    "",
            wantErr: true,
        },
        {
            name:    "invalid - no domain",
            input:   "user@",
            want:    "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := SanitizeEmail(tt.input)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("SanitizeEmail() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if got != tt.want {
                t.Errorf("SanitizeEmail() = %v, want %v", got, tt.want)
            }
        })
    }
}

func TestSanitizeString(t *testing.T) {
    tests := []struct {
        name      string
        input     string
        maxLength int
        want      string
    }{
        {
            name:      "removes dangerous characters",
            input:     "test$command`echo hello`",
            maxLength: 1000,
            want:      "testcommandecho hello",
        },
        {
            name:      "respects length limit",
            input:     "abcdefghijklmnopqrstuvwxyz",
            maxLength: 10,
            want:      "abcdefghij",
        },
        {
            name:      "removes control characters",
            input:     "test\x00\x01\x02string",
            maxLength: 1000,
            want:      "teststring",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := SanitizeString(tt.input, tt.maxLength)
            if got != tt.want {
                t.Errorf("SanitizeString() = %v, want %v", got, tt.want)
            }
        })
    }
}
