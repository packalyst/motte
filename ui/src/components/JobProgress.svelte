<script>
  /**
   * JobProgress — the machine's package job (apply updates, fix packages, kernel update) as it
   * runs: the step, the last lines of output (live, a few seconds behind the machine) and, once
   * it ends, how it went. job is the report's `job`; it follows the machine's live reports.
   * onclose, when given, adds a ✕ to a finished job's card.
   */
  import { timeAgo, formatBanTime } from '$lib/utils/format.js'
  import Icon from './Icon.svelte'

  let { job, onclose = undefined } = $props()

  const TITLE = { 'apply-updates': 'Applying updates', 'fix-packages': 'Upgrading selected packages', 'update-kernel': 'Updating the kernel' }
  const STATE = {
    running: { label: 'Running', cls: 'bg-info/10 text-info' },
    done: { label: 'Done', cls: 'bg-success/10 text-success' },
    failed: { label: 'Failed', cls: 'bg-destructive/10 text-destructive' },
  }
  const st = $derived(STATE[job.status] || STATE.running)
  const secs = (a, b) => Math.max(0, Math.round((new Date(b) - new Date(a)) / 1000))

  // keep the newest line in view as output arrives
  let box = $state()
  $effect(() => { job.lines; if (box) box.scrollTop = box.scrollHeight })
</script>

<div class="mt-4 rounded-lg border border-border bg-muted/30">
  <div class="flex flex-wrap items-center gap-2 px-3 py-2 text-xs">
    <Icon name={job.kind === 'update-kernel' ? 'cpu' : 'download'} size={14} class="text-muted-foreground" />
    <span class="font-medium text-foreground">{TITLE[job.kind] || job.kind}</span>
    <span class="inline-flex items-center gap-1 rounded px-1.5 py-px text-[10px] font-medium {st.cls}">
      {#if job.status === 'running'}<span class="h-1.5 w-1.5 animate-pulse rounded-full bg-current"></span>{/if}{st.label}
    </span>
    {#if onclose && job.status !== 'running'}
      <!-- top-right on a phone (the time drops below); after the time on wider screens -->
      <button type="button" onclick={onclose} aria-label="Close" title="Close"
        class="-mr-1 ml-auto grid h-6 w-6 shrink-0 cursor-pointer place-items-center rounded text-muted-foreground transition hover:bg-muted hover:text-foreground sm:order-last sm:ml-0">
        <Icon name="x" size={14} />
      </button>
    {/if}
    <span class="w-full pl-[22px] tabular-nums text-muted-foreground sm:ml-auto sm:w-auto sm:pl-0">
      {#if job.ended_at}{timeAgo(job.ended_at)} · took {formatBanTime(secs(job.started_at, job.ended_at))}{:else}started {timeAgo(job.started_at)}{/if}
    </span>
  </div>
  {#if job.step}
    <div class="border-t border-dashed border-border px-3 py-1.5 font-mono text-[11px] text-muted-foreground">$ {job.step}</div>
  {/if}
  {#if job.lines?.length && (job.status === 'running' || !job.result)}
    <pre bind:this={box} class="max-h-44 overflow-auto border-t border-dashed border-border px-3 py-2 font-mono text-[11px] leading-relaxed text-foreground/80 whitespace-pre-wrap break-all">{job.lines.join('\n')}</pre>
  {/if}
  {#if job.result && job.status !== 'running'}
    <pre class="max-h-44 overflow-auto border-t border-dashed border-border px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all {job.status === 'failed' ? 'text-destructive' : 'text-foreground/80'}">{job.result}</pre>
  {/if}
</div>
