package certificate

import (
	"encoding/json"
	"encoding/pem"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	zx509 "github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"github.com/smallstep/cli/flags"
)

// webPKISources are the lint families that only apply to publicly-trusted
// certificates. They are skipped unless --profile=webpki is given.
var webPKISources = lint.SourceList{
	lint.CABFBaselineRequirements,
	lint.CABFEVGuidelines,
	lint.CABFSMIMEBaselineRequirements,
	lint.MozillaRootStorePolicy,
	lint.AppleRootStorePolicy,
}

func lintCommand() cli.Command {
	return cli.Command{
		Name:   "lint",
		Action: cli.ActionFunc(lintAction),
		Usage:  `lint certificate details`,
		UsageText: `**step certificate lint** <crt-file> [**--roots**=<root-bundle>]
[**--servername**=<servername>]`,
		Description: `**step certificate lint** checks a certificate for common errors and outputs the result in JSON format. It is intended for evaluating Web PKI certificates, and may not be appropriate for internal PKIs.

## POSITIONAL ARGUMENTS

<crt-file>
:  Path to a certificate or certificate signing request (CSR) to lint.

## EXIT CODES

This command returns 0 on success and \>0 if any error occurs.

## EXAMPLES

'''
$ step certificate lint ./certificate.crt
'''

Lint a remote certificate (using the default root certificate bundle to verify the server):

'''
$ step certificate lint https://smallstep.com
'''

Lint a remote certificate using a custom root certificate to verify the server:

'''
$ step certificate lint https://smallstep.com --roots ./certificate.crt
'''

Lint a remote certificate using a custom list of root certificates to verify the server:

'''
$ step certificate lint https://smallstep.com \
--roots "./certificate.crt,./certificate2.crt,/certificate3.crt"
'''

Lint a remote certificate using a custom directory of root certificates to verify the server:

'''
$ step certificate lint https://smallstep.com --roots "./path/to/certificates/"
'''
`,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name: "roots",
				Usage: `Root certificate(s) that will be used to verify the
authenticity of the remote server.

: <roots> is a case-sensitive string and may be one of:

    **file**
	:  Relative or full path to a file. All certificates in the file will be used for path validation.

    **list of files**
	:  Comma-separated list of relative or full file paths. Every PEM encoded certificate from each file will be used for path validation.

    **directory**
	:  Relative or full path to a directory. Every PEM encoded certificate from each file in the directory will be used for path validation.`,
			},
			cli.StringFlag{
				Name:  "profile",
				Value: "private",
				Usage: `Which lint families to apply.

: <profile> is a case-sensitive string and may be one of:

    **private**
	:  Default. Skips the lint families that only apply to publicly-trusted certificates (CA/Browser Forum, Mozilla and Apple root store policies), leaving RFC and community lints. Appropriate for an internal PKI.

    **webpki**
	:  Applies every lint, including the CA/Browser Forum Baseline Requirements. Appropriate for certificates intended to be publicly trusted.`,
			},
			cli.BoolFlag{
				Name: "insecure",
				Usage: `Use an insecure client to retrieve a remote peer certificate. Useful for
debugging invalid certificates remotely.`,
			},
			flags.ServerName,
		},
	}
}

func lintAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 1); err != nil {
		return err
	}

	var (
		crtFile    = ctx.Args().Get(0)
		roots      = ctx.String("roots")
		serverName = ctx.String("servername")
		insecure   = ctx.Bool("insecure")
		profile    = ctx.String("profile")
		block      *pem.Block
	)
	if profile != "private" && profile != "webpki" {
		return errs.InvalidFlagValue(ctx, "profile", profile, "private, webpki")
	}
	switch addr, isURL, err := trimURL(crtFile); {
	case err != nil:
		return err
	case isURL:
		peerCertificates, err := getPeerCertificates(addr, serverName, roots, insecure)
		if err != nil {
			return err
		}
		crt := peerCertificates[0]
		block = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw,
		}
	default: // is not URL
		crtBytes, err := os.ReadFile(crtFile)
		if err != nil {
			return errs.FileError(err, crtFile)
		}
		block, _ = pem.Decode(crtBytes)
		if block == nil {
			return errors.Errorf("could not parse certificate file '%s'", crtFile)
		}
	}

	zcrt, err := zx509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	registry := lint.GlobalRegistry()
	if profile == "private" {
		registry, err = registry.Filter(lint.FilterOptions{ExcludeSources: webPKISources})
		if err != nil {
			return errors.WithStack(err)
		}
	}

	zlintResult := zlint.LintCertificateEx(zcrt, registry)
	b, err := json.MarshalIndent(struct {
		*zlint.ResultSet
	}{zlintResult}, "", " ")
	if err != nil {
		return errors.WithStack(err)
	}
	os.Stdout.Write(b)

	return nil
}
