import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Pipeline, type Recipe, type Schedule } from "../api";
import { Empty, Managed, StatusPill, when } from "../ui";

export function AutopkgPage() {
  const navigate = useNavigate();
  const [recipes, setRecipes] = useState<Recipe[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [pipeline, setPipeline] = useState<Pipeline | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  useEffect(() => {
    let stop = false;
    const load = () => {
      Promise.all([api.recipes(), api.schedules(), api.pipeline()])
        .then(([r, s, p]) => {
          if (stop) return;
          setRecipes(r.recipes);
          setSchedules(s.schedules);
          setPipeline(p);
          setError("");
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

  const cronFor = (id: string) => schedules.find((s) => s.recipe_id === id && s.enabled)?.cron;

  return (
    <>
      <h1>AutoPkg</h1>
      <p className="lede">Recipes, schedules, and pipeline limits are applied by Terraform. This page only shows status and lets you start a run.</p>
      {error && <p className="lede">{error}</p>}
      {pipeline && (
        <div className="panel strip">
          <span><strong>{pipeline.max_concurrency}</strong> at once</span>
          <span><strong>{pipeline.per_runner_parallelism}</strong> per runner</span>
          <span><strong>{pipeline.timeout_seconds}s</strong> timeout</span>
          <span><strong>{pipeline.max_retries}</strong> retries</span>
          <span><strong>{pipeline.lease_seconds}s</strong> lease</span>
          <Managed />
        </div>
      )}
      <div className="panel">
        {recipes.length === 0 ? (
          <Empty>No recipes yet. They appear when Terraform applies.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Recipe</th>
                <th>Schedule</th>
                <th>Last run</th>
                <th></th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {recipes.map((recipe) => (
                <tr key={recipe.id}>
                  <td>
                    <div className="name">{recipe.name}</div>
                    <div className="sub">{recipe.identifier}{recipe.enabled ? "" : " · disabled"}</div>
                  </td>
                  <td className="sub">{cronFor(recipe.id) ?? "—"}</td>
                  <td>
                    {recipe.last_job ? (
                      <Link to={`/runs/${recipe.last_job.id}`}>
                        <StatusPill status={recipe.last_job.status} result={recipe.last_job.result} />
                      </Link>
                    ) : (
                      <span className="sub">no runs</span>
                    )}
                    <div className="sub">{when(recipe.last_job?.finished_at || recipe.last_job?.created_at)}</div>
                  </td>
                  <td>{recipe.managed_by === "terraform" ? <Managed /> : <span className="pill">{recipe.managed_by}</span>}</td>
                  <td>
                    <button
                      className="btn quiet"
                      disabled={!recipe.enabled || busy === recipe.id}
                      onClick={() => {
                        setBusy(recipe.id);
                        api.runNow(recipe.id)
                          .then((job) => navigate(`/runs/${job.id}`))
                          .catch((err: Error) => setError(err.message))
                          .finally(() => setBusy(""));
                      }}
                    >
                      Run now
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
