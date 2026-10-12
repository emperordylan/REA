import { existsSync, statSync } from "node:fs";
import { join, win32 } from "node:path";

/** Resolve Windows bare command names against the captured child environment. */
export const resolveWindowsProviderExecutable = (
  executable: string,
  environment: Readonly<NodeJS.ProcessEnv>,
): string => {
  if (
    win32.isAbsolute(executable) ||
    executable.includes("/") ||
    executable.includes("\\")
  )
    return executable;

  const pathValue = environment.PATH ?? environment.Path ?? environment.path;
  if (pathValue === undefined) return executable;
  const pathEntries = pathValue.split(";");
  const explicitExtension = win32.extname(executable).toLowerCase();
  if (explicitExtension !== "" && ![".com", ".exe"].includes(explicitExtension))
    return executable;
  const extensions =
    explicitExtension !== ""
      ? [""]
      : (environment.PATHEXT ?? environment.PathExt ?? ".COM;.EXE")
          .split(";")
          .filter((extension) =>
            [".com", ".exe"].includes(extension.toLowerCase()),
          );

  for (const entry of pathEntries) {
    if (entry.length === 0) continue;
    for (const extension of extensions) {
      const candidate = join(entry, `${executable}${extension}`);
      // The captured PATH is Windows-formatted even when this resolver is unit-tested elsewhere.
      try {
        if (existsSync(candidate) && statSync(candidate).isFile())
          return candidate;
      } catch {
        // An inaccessible PATH entry is equivalent to a missing candidate.
      }
    }
  }
  return executable;
};
