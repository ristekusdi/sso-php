<?php

namespace RistekUSDI\SSO\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Illuminate\Filesystem\Filesystem;

class Copy extends Command
{
    /**
     * The name of the command (the part after "bin/sso").
     *
     * @var string
     */
    protected static $defaultName = 'copy:ci3';

    /**
     * The command description shown when running "php bin/sso list".
     *
     * @var string
     */
    protected static $defaultDescription = 'Copy SSO files for CodeIgniter 3.x!';

    /**
     * Execute the command
     *
     * @param  InputInterface  $input
     * @param  OutputInterface $output
     * @return int 0 if everything went fine, or an exit code.
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        (new Filesystem)->copyDirectory(__DIR__.'/../../stubs/ci3', 'application');
        $output->writeln('Copy success!');
        return Command::SUCCESS;
    }
}