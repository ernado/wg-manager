package main

import (
	_ "embed"
	"text/template"

	"github.com/go-faster/errors"
	"github.com/spf13/cobra"
)

func ClientCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "client",
		Short:        "Client management",
		Long:         "Manage WireGuard clients.",
		SilenceUsage: true,
	}

	cmd.AddCommand(
		ClientConfigCommand(),
	)

	return cmd
}

func clientNameCompletion(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg, err := ReadConfig()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var completions []cobra.Completion
	for _, peer := range cfg.Peers {
		if peer.Name == "" {
			continue
		}
		completions = append(completions, peer.Name)
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
}

type ClientConfig struct {
	Peer      Peer
	Endpoint  string // IP:Port or Hostname:Port
	PublicKey Key
}

//go:embed client.conf.tmpl
var clientConfigTemplate string

func ClientConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "config [name]",
		Short:             "Generate WireGuard client configuration",
		Long:              "Generate WireGuard client configuration file.",
		SilenceUsage:      true,
		ValidArgsFunction: clientNameCompletion,
		Args:              cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientName := args[0]

			cfg, err := ReadConfig()
			if err != nil {
				return errors.Wrap(err, "failed to read configuration")
			}

			for _, peer := range cfg.Peers {
				if peer.Name != clientName {
					continue
				}

				// Found the peer, generate the configuration.
				clientConfig := ClientConfig{
					Peer:      peer,
					Endpoint:  cfg.Endpoint,
					PublicKey: Key(cfg.PrivateKey.Public()),
				}
				tmpl, err := template.New("clientConfig").Parse(clientConfigTemplate)
				if err != nil {
					return errors.Wrap(err, "failed to parse template")
				}
				if err := tmpl.Execute(cmd.OutOrStdout(), clientConfig); err != nil {
					return errors.Wrap(err, "failed to execute template")
				}

				return nil
			}

			return errors.Errorf("client with name %q not found", clientName)
		},
	}

	return cmd
}
