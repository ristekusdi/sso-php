<?php

namespace RistekUSDI\SSO\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Illuminate\Filesystem\Filesystem;

class Copy extends Command
{
    /**
     * The name of the command (the part after "bin/sso").
     *
     * @var string
     */
    protected static $defaultName = 'copy:file';

    /**
     * The command description shown when running "php bin/sso list".
     *
     * @var string
     */
    protected static $defaultDescription = 'Copy SSO files!';

    protected function configure(): void
    {
        $this->addOption(
            'type',
            null,
            InputOption::VALUE_REQUIRED,
            'Which type you want to Copy SSO file',
            ['php', 'ci3']
        );
    }

    /**
     * Execute the command
     *
     * @param  InputInterface  $input
     * @param  OutputInterface $output
     * @return int 0 if everything went fine, or an exit code.
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $type = $input->getOption('type');
        if ($type === "php") {
            (new Filesystem)->copyDirectory(__DIR__.'/../../stubs/php', 'sso');
            $output->writeln('Copy success!');
        } else if ($type === "ci3") {
            (new Filesystem)->copyDirectory(__DIR__.'/../../stubs/ci3', 'application');
            $output->writeln('Copy success!');
        }

        return Command::SUCCESS;
    }
}