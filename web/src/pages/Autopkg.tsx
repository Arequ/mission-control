import { useEffect, useState, type CSSProperties } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Pipeline, type Recipe, type Schedule } from "../api";
import { describeCron } from "../cron";
import { Icon } from "../icons";
import { AutopkgSeg, Empty, Managed, Mark, Page, StatusPill, Toolbar, enterStyle, match, useSearch, when } from "../ui";

type View = "list" | "icons";
type Sort = "name" | "name-desc" | "recent" | "status";

const SORTS: { value: Sort; label: string }[] = [
  { value: "name", label: "Name A–Z" },
  { value: "name-desc", label: "Name Z–A" },
  { value: "recent", label: "Last run" },
  { value: "status", label: "Needs attention" },
];

const VIEW_KEY = "mc.autopkg.view";
const SORT_KEY = "mc.autopkg.sort";

function stored<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key) as T | null;
    return v && allowed.includes(v) ? v : fallback;
  } catch {
    return fallback;
  }
}

function remember(key: string, value: string) {
  try { localStorage.setItem(key, value); } catch { /* private mode */ }
}

// Lower ranks sort first under "Needs attention": broken runs, then live ones, then new builds.
function attention(recipe: Recipe) {
  const key = recipe.last_job?.result || recipe.last_job?.status || "";
  if (["failed", "error", "trust_failed"].includes(key)) return 0;
  if (["running", "leased", "queued"].includes(key)) return 1;
  if (key === "new_version") return 2;
  if (!recipe.last_job) return 4;
  return 3;
}

function lastRun(recipe: Recipe) {
  const at = recipe.last_job?.finished_at || recipe.last_job?.created_at;
  return at ? Date.parse(at) : 0;
}

function sortRecipes(list: Recipe[], sort: Sort) {
  const byName = (a: Recipe, b: Recipe) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
  const out = [...list];
  switch (sort) {
    case "name-desc": return out.sort((a, b) => byName(b, a));
    case "recent": return out.sort((a, b) => lastRun(b) - lastRun(a) || byName(a, b));
    case "status": return out.sort((a, b) => attention(a) - attention(b) || byName(a, b));
    default: return out.sort(byName);
  }
}

export function AutopkgPage() {
  const navigate = useNavigate();
  const { q } = useSearch();
  const [recipes, setRecipes] = useState<Recipe[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [pipeline, setPipeline] = useState<Pipeline | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  // Run errors stay until the next run; the 4s poll only clears its own load error.
  const [runError, setRunError] = useState("");
  const [view, setView] = useState<View>(() => stored(VIEW_KEY, ["list", "icons"] as const, "list"));
  const [sort, setSort] = useState<Sort>(() => stored(SORT_KEY, SORTS.map((s) => s.value), "name"));

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

  const scheduleFor = (id: string) => schedules.find((s) => s.recipe_id === id && s.enabled);
  const shown = sortRecipes(recipes.filter((recipe) => {
    const schedule = scheduleFor(recipe.id);
    return match(q, recipe.name, recipe.identifier, schedule?.cron, schedule ? describeCron(schedule.cron) : "");
  }), sort);

  const runNow = (recipe: Recipe) => {
    setBusy(recipe.id);
    setRunError("");
    api.runNow(recipe.id)
      .then((job) => navigate(`/runs/${job.id}`))
      .catch((err: Error) => setRunError(`${recipe.name}: ${err.message}`))
      .finally(() => setBusy(""));
  };

  const pickView = (next: View) => { setView(next); remember(VIEW_KEY, next); };
  const pickSort = (next: Sort) => { setSort(next); remember(SORT_KEY, next); };

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
        {runError ? <p className="note" role="alert">{runError}</p> : null}
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
        <section className={`card enter${view === "icons" ? " card-tiles" : ""}`} style={enterStyle(1)}>
          <div className="card-h">
            <span className="card-t">Recipes</span>
            <span className="faint">{shown.length}</span>
            <div className="recipe-tools">
              <select className="field select sort" aria-label="Sort recipes" value={sort} onChange={(e) => pickSort(e.target.value as Sort)}>
                {SORTS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
              <div className="seg view-seg" role="group" aria-label="View" style={{ "--n": 2, "--i": view === "list" ? 0 : 1 } as CSSProperties}>
                <span className="seg-thumb" />
                <button type="button" className={view === "list" ? "on" : undefined} aria-pressed={view === "list"} title="List" aria-label="List view" onClick={() => pickView("list")}>
                  <Icon name="list" size={14} />
                </button>
                <button type="button" className={view === "icons" ? "on" : undefined} aria-pressed={view === "icons"} title="Icons" aria-label="Icon view" onClick={() => pickView("icons")}>
                  <Icon name="grid" size={14} />
                </button>
              </div>
            </div>
          </div>
          {shown.length === 0 ? (
            <Empty>{recipes.length === 0 ? "No recipes yet. They appear when Terraform applies." : "Nothing matches."}</Empty>
          ) : view === "icons" ? (
            <div className="tiles" key={`icons-${sort}`}>
              {shown.map((recipe, index) => {
                const schedule = scheduleFor(recipe.id);
                // The entrance animation lives on the wrapper: its fill would pin the tile's transform and block the hover lift.
                return (
                  <div key={recipe.id} className="tile-cell enter" style={enterStyle(Math.min(index, 24))}>
                  <article className={`tile${recipe.enabled ? "" : " off"}`}>
                    <span className="tile-glow" />
                    {recipe.managed_by === "terraform" ? <span className="tile-lock"><Managed small /></span> : null}
                    <div className="tile-art"><Mark name={recipe.name} size="xl" /></div>
                    <div className="tile-name" title={recipe.name}>{recipe.name}</div>
                    <div className="tile-sub mono" title={recipe.identifier}>{recipe.identifier}</div>
                    <div className="tile-sched" title={schedule?.cron}>
                      {schedule ? describeCron(schedule.cron) : "No schedule"}
                      {recipe.enabled ? "" : " · disabled"}
                    </div>
                    <div className="tile-foot">
                      {recipe.last_job ? (
                        <Link to={`/runs/${recipe.last_job.id}`} title={when(recipe.last_job.finished_at || recipe.last_job.created_at)}>
                          <StatusPill status={recipe.last_job.status} result={recipe.last_job.result} />
                        </Link>
                      ) : <span className="faint">No runs</span>}
                      <RunNow recipe={recipe} busy={busy === recipe.id} onRun={runNow} />
                    </div>
                  </article>
                  </div>
                );
              })}
            </div>
          ) : (
            <>
              <div className="list-h cols-recipe">
                <span>Recipe</span><span>Schedule</span><span>Last run</span><span></span><span></span>
              </div>
              {shown.map((recipe, index) => {
                const schedule = scheduleFor(recipe.id);
                return (
                  <div key={recipe.id} className="row cols-recipe enter" style={enterStyle(Math.min(index, 24))}>
                    <span className="wash" />
                    <div className="who">
                      <Mark name={recipe.name} />
                      <div className="id">
                        <div className="name">{recipe.name}{recipe.enabled ? "" : " · disabled"}</div>
                        <div className="subline mono">{recipe.identifier}</div>
                      </div>
                    </div>
                    <div
                      className="cron-cell muted"
                      title={schedule ? `${schedule.cron}${schedule.timezone && schedule.timezone !== "UTC" ? ` ${schedule.timezone}` : ""}` : undefined}
                    >
                      {schedule ? describeCron(schedule.cron) : "—"}
                    </div>
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
                      <RunNow recipe={recipe} busy={busy === recipe.id} onRun={runNow} />
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </section>
      </div>
    </Page>
  );
}

function RunNow({ recipe, busy, onRun }: { recipe: Recipe; busy: boolean; onRun: (recipe: Recipe) => void }) {
  return (
    <button className="capsule primary" type="button" disabled={!recipe.enabled || busy} onClick={() => onRun(recipe)}>
      <Icon name="play" size={12} />
      Run now
    </button>
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
