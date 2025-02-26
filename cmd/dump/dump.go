package dump

import (
	"github.com/openshift/hypershift/cmd/cluster/core"

	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "dump",
		Short:        "Commands for dumping resources for debugging",
		SilenceUsage: true,
	}

	cmd.AddCommand(core.NewDumpCommand())

	return cmd
}
