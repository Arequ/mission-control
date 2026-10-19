import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Job } from "../api";
import { Empty, StatusPill, when } from "../ui";

export function RunsPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let stop = false;
    const load = () => {
      api.jobs()
        .then((res) => {
          if (!stop) setJobs(res.jobs);
        })
        .catch((err: Error) => {
          if (!stop) setError(err.message);
        });
    };
    load();
    const t = setInterval(load, 4000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);
  return (
    <>
      <h1>Runs</h1>
      <p className="lede">Each row is one AutoPkg execution, scheduled or started by hand.</p>
      {error && <p className="lede">{error}</p>}
      <div className="panel">
        {jobs.length === 0 ? (
          <Empty>No runs yet.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Recipe</th>
                <th>Trigger</th>
                <th>Status</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td>
                    <Link to={`/runs/${job.id}`} className="name">{job.recipe_name || job.recipe_identifier}</Link>
                    <div className="sub">attempt {job.attempt}/{job.max_attempts}</div>
                  </td>
                  <td className="sub">{job.trigger}</td>
                  <td><StatusPill status={job.status} result={job.result} /></td>
                  <td className="sub">{when(job.finished_at || job.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
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
        .then((next) => {
          if (!stop) setJob(next);
        })
        .catch((err: Error) => {
          if (!stop) setError(err.message);
        });
    };
    load();
    const t = setInterval(load, 2000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [id]);
  if (error) return <p className="lede">{error}</p>;
  if (!job) return <p className="lede">Loading…</p>;
  const lines = job.logs ?? [];
  return (
    <>
      <h1>{job.recipe_name || "Run"}</h1>
      <p className="lede">
        <StatusPill status={job.status} result={job.result} />{" "}
        <span className="sub">
          {job.trigger} · attempt {job.attempt}/{job.max_attempts}
          {job.runner_name ? ` · ${job.runner_name}` : ""}
          {terminal.has(job.status) ? "" : " · live"}
        </span>
      </p>
      {job.error && <p className="lede">{job.error}</p>}
      <pre className="log">
        {lines.length === 0 ? "Waiting for output…" : lines.map((line) => (
          <span key={line.id} className={line.stream === "stderr" ? "err" : undefined}>
            {line.line}
            {"\n"}
          </span>
        ))}
      </pre>
    </>
  );
}
