import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Job } from "../api";
import { AutopkgSeg, Empty, Mark, Page, StatusPill, Toolbar, enterStyle, match, useSearch, when } from "../ui";

export function RunsPage() {
  const { q } = useSearch();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.jobs()
        .then((res) => { if (!stop) setJobs(res.jobs); })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 4000);
    return () => { stop = true; clearInterval(t); };
  }, []);
  const shown = jobs.filter((job) => match(q, job.recipe_name, job.recipe_identifier, job.trigger, job.result, job.status, job.runner_name));
  return (
    <Page>
      <Toolbar title="Runs" lede="One row is one AutoPkg execution, scheduled or started by hand." extra={<AutopkgSeg />} />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        <section className="card">
          {shown.length === 0 ? (
            <Empty>{jobs.length === 0 ? "No runs yet." : "Nothing matches."}</Empty>
          ) : (
            <>
              <div className="list-h cols-run">
                <span>Recipe</span><span>Trigger</span><span>Result</span><span>Attempt</span><span className="right">When</span>
              </div>
              {shown.map((job, index) => (
                <Link key={job.id} to={`/runs/${job.id}`} className="row cols-run enter" style={enterStyle(index)}>
                  <span className="wash" />
                  <div className="who">
                    <Mark name={job.recipe_name || job.recipe_identifier || "Run"} />
                    <div className="id">
                      <div className="name">{job.recipe_name || job.recipe_identifier}</div>
                      <div className="subline mono">{job.recipe_identifier}</div>
                    </div>
                  </div>
                  <div className="muted">{job.trigger}</div>
                  <div><StatusPill status={job.status} result={job.result} /></div>
                  <div className="mono muted">{job.attempt}/{job.max_attempts}</div>
                  <div className="muted right">{when(job.finished_at || job.created_at)}</div>
                </Link>
              ))}
            </>
          )}
        </section>
      </div>
    </Page>
  );
}

const terminal = new Set(["succeeded", "failed"]);

export function RunDetailPage() {
  const { id = "" } = useParams();
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.job(id)
        .then((next) => { if (!stop) setJob(next); })
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 2000);
    return () => { stop = true; clearInterval(t); };
  }, [id]);
  return (
    <Page>
      <Toolbar
        title={job?.recipe_name || "Run"}
        lede={job ? `${job.trigger} · attempt ${job.attempt}/${job.max_attempts}${job.runner_name ? ` · ${job.runner_name}` : ""}${job && terminal.has(job.status) ? "" : " · live"}` : "Loading the run"}
        extra={<AutopkgSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        {job ? (
          <>
            <div className="title-row">
              <StatusPill status={job.status} result={job.result} />
              <span className="faint">{when(job.finished_at || job.started_at || job.created_at)}</span>
            </div>
            {job.error ? <p className="note">{job.error}</p> : null}
            <pre className="log">
              {(job.logs ?? []).length === 0 ? "Waiting for output…" : (job.logs ?? []).map((line) => (
                <span key={line.id} className={line.stream === "stderr" ? "err" : undefined}>{line.line}{"\n"}</span>
              ))}
            </pre>
          </>
        ) : !error ? <p className="faint">Loading…</p> : null}
      </div>
    </Page>
  );
}
