import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Pipeline, type Recipe, type Schedule } from "../api";
import { AutopkgSeg, Empty, Managed, Mark, Page, StatusPill, Toolbar, enterStyle, match, useSearch, when } from "../ui";

export function AutopkgPage() {
  const navigate = useNavigate();
  const { q } = useSearch();
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
        .catch((err: Error) => { if (!stop) setError(err.message); });
    };
    load();
    const t = setInterval(load, 4000);
    return () => { stop = true; clearInterval(t); };
  }, []);

  const cronFor = (id: string) => schedules.find((s) => s.recipe_id === id && s.enabled)?.cron;
  const shown = recipes.filter((recipe) => match(q, recipe.name, recipe.identifier, cronFor(recipe.id)));

  return (
    <Page>
      <Toolbar
        title="AutoPKG"
        badge
        lede="Recipes, schedules, and limits are applied by Terraform. Run now is the only action here."
        extra={<AutopkgSeg />}
      />
      <div className="content">
        {error ? <p className="note">{error}</p> : null}
        {pipeline ? (
          <section className="card enter" style={enterStyle(0)}>
            <div className="card-h">
              <span className="card-t">Pipeline</span>
              {pipeline.managed_by === "terraform" ? <Managed small /> : null}
              <span className="faint" style={{ marginLeft: "auto" }}>Lease {pipeline.lease_seconds}s</span>
            </div>
            <div className="stats">
              <Stat value={String(pipeline.max_concurrency)} label="At once" />
              <Stat value={String(pipeline.per_runner_parallelism)} label="Per runner" />
              <Stat value={`${pipeline.timeout_seconds}s`} label="Timeout" />
              <Stat value={String(pipeline.max_retries)} label="Retries" />
            </div>
          </section>
        ) : null}
        <section className="card enter" style={enterStyle(1)}>
          <div className="card-h">
            <span className="card-t">Recipes</span>
            <span className="faint">{shown.length}</span>
          </div>
          {shown.length === 0 ? (
            <Empty>{recipes.length === 0 ? "No recipes yet. They appear when Terraform applies." : "Nothing matches."}</Empty>
          ) : (
            <>
              <div className="list-h cols-recipe">
                <span>Recipe</span><span>Schedule</span><span>Last run</span><span></span><span></span>
              </div>
              {shown.map((recipe, index) => (
                <div key={recipe.id} className="row cols-recipe enter" style={enterStyle(index)}>
                  <span className="wash" />
                  <div className="who">
                    <Mark name={recipe.name} />
                    <div className="id">
                      <div className="name">{recipe.name}{recipe.enabled ? "" : " · disabled"}</div>
                      <div className="subline mono">{recipe.identifier}</div>
                    </div>
                  </div>
                  <div className="mono muted">{cronFor(recipe.id) ?? "—"}</div>
                  <div>
                    {recipe.last_job ? (
                      <Link to={`/runs/${recipe.last_job.id}`}>
                        <StatusPill status={recipe.last_job.status} result={recipe.last_job.result} />
                      </Link>
                    ) : <span className="faint">No runs</span>}
                    <div className="subline">{when(recipe.last_job?.finished_at || recipe.last_job?.created_at)}</div>
                  </div>
                  <div>{recipe.managed_by === "terraform" ? <Managed small /> : <span className="pill gray">{recipe.managed_by}</span>}</div>
                  <div className="end">
                    <button
                      className="capsule primary"
                      type="button"
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
                  </div>
                </div>
              ))}
            </>
          )}
        </section>
      </div>
    </Page>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="stat">
      <b className="tnum">{value}</b>
      <span>{label}</span>
    </div>
  );
}
