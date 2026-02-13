import { getDependabotConfig } from '@paklo/core/azure';
import {
  DEPENDABOT_DEFAULT_AUTHOR_EMAIL,
  DEPENDABOT_DEFAULT_AUTHOR_NAME,
  type GitAuthor,
} from '@paklo/core/dependabot';
import { logger } from '@paklo/core/logger';
import type { SecretMasker } from '@paklo/runner';
import { AzureLocalJobsRunner, type AzureLocalJobsRunnerOptions } from '@paklo/runner/local/azure';
import * as tl from 'azure-pipelines-task-lib/task';
import { setSecrets } from '../formatting';
import { getTaskInputs } from './inputs';

async function run() {
  try {
    // Check if required tools are installed
    tl.debug('Checking for `docker` install...');
    tl.which('docker', true);

    // Parse task input configuration
    const inputs = getTaskInputs();
    if (!inputs) {
      throw new Error('Failed to parse task input configuration');
    }

    // update logger level based on debug input
    logger.level = inputs.debug ? 'debug' : 'warn';

    const { url, authorEmail, authorName, ...remainingInputs } = inputs;

    // Parse dependabot configuration file
    const config = await getDependabotConfig({
      url,
      token: inputs.systemAccessToken,
      remote: inputs.repositoryOverridden, // fetch remotely if the repository is overridden
      rootDir: tl.getVariable('Build.SourcesDirectory')!,
      variableFinder: tl.getVariable,
    });
    if (!config) {
      throw new Error('Failed to parse dependabot.yaml configuration file from the target repository');
    }

    // Create a secret masker for Azure Pipelines
    const secretMasker: SecretMasker = (value: string) => (inputs.secrets ? setSecrets(value) : value);

    // Create the author object
    const author: GitAuthor = {
      name: authorName || DEPENDABOT_DEFAULT_AUTHOR_NAME,
      email: authorEmail || DEPENDABOT_DEFAULT_AUTHOR_EMAIL,
    };

    // Setup the jobs runner options
    const runnerOptions: AzureLocalJobsRunnerOptions = {
      ...remainingInputs,
      command: 'update',
      config,
      port: inputs.dependabotApiPort,
      url,
      secretMasker,
      gitToken: inputs.systemAccessToken,
      githubToken: inputs.githubAccessToken,
      author,
      autoApproveToken: inputs.autoApproveUserToken,
    };

    // Run the Azure Local Jobs Runner
    const runner = new AzureLocalJobsRunner(runnerOptions);
    const result = await runner.run();
    const success = result.every((r) => r.success);

    if (success) {
      tl.setResult(tl.TaskResult.Succeeded, 'All update tasks completed successfully');
    } else {
      let message = result
        .map((r) => r.message)
        .join('\n')
        .trim();
      if (message.length === 0) {
        message = 'Update tasks failed. Check the logs for more information';
      }
      tl.setResult(tl.TaskResult.Failed, message);
    }

    // Collect unique list of all affected PRs and set it as an output variable
    const prs = Array.from(new Set(result.flatMap((r) => r.affectedPrs)));

    tl.setVariable(
      'affectedPrs', // name
      prs.join(','), // value
      false, // secret
      true, // isOutput
    );
  } catch (e) {
    const err = e as Error;
    tl.setResult(tl.TaskResult.Failed, err.message);
    tl.error(`An unhandled exception occurred: ${e}`);
    console.debug(e); // Dump the stack trace to help with debugging
  }
}

// Explicitly exit the process after the async run() completes.
//
// Why is process.exit() required?
// Node.js normally exits automatically when the event loop has no more work, but in this case
// several background resources keep the event loop alive even after the task "completes":
//
// 1. Docker Socket Connections (@paklo/runner/src/cleanup.ts):
//    - The cleanup function creates Docker() instances but never closes them
//    - Open Docker socket connections to the daemon keep file descriptors alive
//    - The callback-based docker.listImages() API fires async operations that outlive cleanup()
//
// 2. HTTP Server (@paklo/runner/src/local/server.ts):
//    - The Hono server is stopped via server.close() but may have lingering connections
//    - Node's http.Server.close() only stops accepting new connections, existing ones may remain
//
// 3. Timers and Async Operations:
//    - Various setTimeout() calls throughout the runner for Docker operations
//    - Async Docker image operations that complete after the main flow finishes
//
// These are implementation details in the @paklo/runner package. Rather than refactoring
// the entire cleanup and server lifecycle (which would be a larger change affecting multiple
// platforms), we explicitly signal process termination here in the Azure extension task handler.
//
// This is the recommended approach for Azure Pipelines Node 20/24 handlers per Microsoft's
// guidance when background operations cannot be easily awaited or canceled.
run()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error('Unhandled promise rejection:', err);
    process.exit(1);
  });
