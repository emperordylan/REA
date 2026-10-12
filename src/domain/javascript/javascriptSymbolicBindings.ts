import * as t from "@babel/types";
import {
  semanticStaticPropertyKey,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";
import { javascriptBootstrapAt } from "./javascriptBootstrap.js";
import {
  ELECTRON_MODULE,
  electronExportPath,
  electronMemberPath,
} from "./javascriptElectronMemberWrites.js";
import {
  indexJavaScriptElectronIdentitySteps,
  type JavaScriptElectronIdentity,
} from "./javascriptSemanticAnalysis.js";
import { symbolicLogicalRight } from "./javascriptSymbolicControlFlow.js";
import {
  moduleFactory,
  modulePropertyName,
} from "./javascriptStaticAnalysisHelpers.js";
import {
  childNodes,
  completeSemanticSteps,
  traverseJavaScriptAst,
} from "./javascriptSemanticTraversal.js";
import {
  resolveSemanticBindingState,
  semanticResolutionBlocked,
  type JavaScriptSemanticAnalysisState,
  type JavaScriptSemanticBindingState,
} from "./javascriptSemanticState.js";
import {
  symbolicCondition,
  symbolicUnion,
  symbolicUnknown,
  symbolicVariants,
  symbolicConditionsUnresolved,
  symbolicTruth,
  type SymbolicCondition,
  type SymbolicValue,
  type SymbolicEnvironment,
  type SymbolicFunction,
} from "./javascriptSymbolicValues.js";

interface PropertyWrite {
  readonly path: readonly (string | null)[];
  readonly value: t.Node;
  readonly site: t.Node;
}
interface OriginPropertyWrite {
  readonly source: PropertyWrite;
  readonly path: readonly (string | null)[];
  readonly value: SymbolicValue;
  readonly definite: boolean;
}
interface OriginProperties {
  readonly values: readonly SymbolicValue[];
  readonly definiteKeys: ReadonlySet<string>;
}
const originSnapshot = Symbol("mutation origin snapshot");
type OriginValue = SymbolicValue & {
  readonly [originSnapshot]?: {
    readonly base: SymbolicValue;
    readonly writes: readonly OriginPropertyWrite[];
    readonly end?: number;
    readonly reference?: true;
  };
};
type OriginObjectValue = Extract<
  SymbolicValue,
  { kind: "object" | "record" | "array" }
>;
interface OriginReference {
  readonly binding: JavaScriptSemanticBindingState;
  readonly node: t.Identifier;
  readonly environment: SymbolicEnvironment;
  readonly path: readonly string[];
}
interface SymbolicReturnFlow {
  readonly values: readonly SymbolicValue[];
  readonly fallsThrough: boolean;
}
const emptyEnvironment: SymbolicEnvironment = { values: new Map() };

/** Demand-driven substitutions for local bindings, closures and literal module tables. */
export class JavaScriptSymbolicBindings {
  readonly #writes = new Map<string, PropertyWrite[]>();
  readonly #environments = new WeakMap<t.Node, SymbolicEnvironment>();
  readonly #cache = new WeakMap<
    SymbolicEnvironment,
    WeakMap<t.Node, SymbolicValue>
  >();
  #originCache:
    | WeakMap<SymbolicEnvironment, WeakMap<t.Node, SymbolicValue>>
    | undefined;
  #originPoint: t.Node | undefined;
  #originPointAfter = false;
  readonly #originReferences = new WeakMap<
    SymbolicEnvironment,
    WeakMap<t.ObjectExpression, OriginReference[]>
  >();
  readonly #originCollectionReferences = new WeakMap<
    object,
    OriginReference[]
  >();
  readonly #active = new Set<t.Node>();
  readonly #activeFunctions = new Set<t.Function>();
  readonly #exportAliases = new Map<string, string>();
  readonly #moduleBindings = new Set<string>();
  readonly #replacements = new Map<string, t.Node>();
  readonly #propertyActive = new WeakMap<object, Set<string>>();
  readonly #literalPropertyIndex = new WeakMap<
    t.ObjectExpression,
    ReadonlyMap<string, t.ObjectMethod | t.ObjectProperty> | null
  >();
  readonly #mutated = new Set<string>();
  readonly #electronIdentity: JavaScriptElectronIdentity;
  readonly #namespaceOwners = new Map<string, t.Function>();
  readonly #unsafeExports = new Set<string>();
  readonly #aliasesByBinding = new Map<string, string[]>();
  readonly #bootstrapTables: Array<{
    readonly tableAliases: ReadonlySet<string>;
    readonly modules: Map<string, SymbolicValue>;
  }> = [];
  #remainingEvaluations = 1_000_000;
  #depth = 0;
  truncated = false;
  unresolved = false;

  constructor(
    readonly state: JavaScriptSemanticAnalysisState,
    program: t.Program,
    electronIdentity = completeSemanticSteps(
      indexJavaScriptElectronIdentitySteps(program, state),
    ),
  ) {
    this.#electronIdentity = electronIdentity;
    this.#indexBindingAliases();
    traverseJavaScriptAst(program, {
      enter: (node) => {
        if (t.isCallExpression(node)) this.#indexBootstrap(node);
      },
    });
    traverseJavaScriptAst(program, {
      enter: (node) => {
        if (t.isAssignmentExpression(node))
          this.#indexWrite(node.left, node.right, node);
        if (t.isUpdateExpression(node))
          this.#indexWrite(node.argument, node, node);
        if (t.isUnaryExpression(node, { operator: "delete" }))
          this.#indexWrite(node.argument, node, node);
        if (
          t.isCallExpression(node) &&
          t.isMemberExpression(node.callee) &&
          t.isIdentifier(node.callee.object, { name: "Object" }) &&
          !resolveSemanticBindingState(state, node.callee.object, "Object") &&
          semanticStaticPropertyKey(
            node.callee.property,
            node.callee.computed,
          ) === "defineProperty"
        ) {
          const [target, key, descriptor] = node.arguments;
          if (
            t.isIdentifier(target) &&
            t.isStringLiteral(key) &&
            t.isObjectExpression(descriptor)
          ) {
            const value = descriptor.properties.find(
              (p) =>
                t.isObjectProperty(p) &&
                semanticStaticPropertyKey(p.key, p.computed) === "value",
            );
            if (t.isObjectProperty(value))
              this.#addWrite(target, [key.value], value.value, node);
          }
        }
      },
    });
    for (const table of this.#bootstrapTables)
      this.#invalidateBootstrapTable(table.tableAliases, table.modules);
    const unresolved = this.unresolved;
    this.#originCache = new WeakMap();
    try {
      completeSemanticSteps(
        electronIdentity.enrichWritesSteps((target) =>
          this.#atOriginPoint(target, () =>
            this.#symbolicElectronWritePaths(target),
          ),
        ),
      );
      if (this.truncated) electronIdentity.invalidateAll();
    } finally {
      // Origin discovery sees pre-mutation identities only. Never reuse those
      // values or incidental read-availability flags in ordinary substitutions.
      this.#originCache = undefined;
      this.#originPoint = undefined;
      this.unresolved = unresolved;
    }
  }

  environmentAt(node: t.Node): SymbolicEnvironment {
    let current: t.Node | undefined = node;
    while (current) {
      const found = this.#environments.get(current);
      if (found) return found;
      current = this.state.parentsByNode.get(current);
    }
    return emptyEnvironment;
  }

  evaluate(
    input: t.Node | null | undefined,
    environment?: SymbolicEnvironment,
  ): SymbolicValue {
    if (!input) return { kind: "literal", value: undefined };
    if (--this.#remainingEvaluations < 0 || this.#depth >= 128) {
      this.truncated = true;
      return symbolicUnknown("symbolic resource limit");
    }
    const node = unwrapJavaScriptExpression(input).node;
    const env = environment ?? this.environmentAt(node);
    const caches = this.#originCache ?? this.#cache;
    const cache = caches.get(env) ?? new WeakMap<t.Node, SymbolicValue>();
    caches.set(env, cache);
    const cached = cache.get(node);
    if (cached) return cached;
    if (this.#active.has(node)) return symbolicUnknown("cyclic binding");
    this.#active.add(node);
    this.#depth += 1;
    try {
      const value = this.#evaluate(node, env);
      cache.set(node, value);
      return value;
    } finally {
      this.#active.delete(node);
      this.#depth -= 1;
    }
  }

  property(value: SymbolicValue, key: string): SymbolicValue {
    let result: SymbolicValue;
    if (this.#originCache !== undefined) {
      const found = this.#originProperties(value, key).values;
      result =
        found.length > 0
          ? symbolicUnion(found)
          : symbolicUnknown("unresolved mutation receiver");
    } else if (value.kind === "union")
      result = symbolicUnion(
        value.values.map((variant) => this.property(variant, key)),
      );
    else result = this.#property(value, key);
    for (const condition of value.conditions ?? [])
      result = symbolicCondition(result, condition);
    if (value.conditionUnresolved)
      result = symbolicConditionsUnresolved(result);
    return result;
  }

  #property(value: SymbolicValue, key: string): SymbolicValue {
    const active = this.#propertyActive.get(value) ?? new Set<string>();
    if (active.has(key)) return symbolicUnknown("cyclic property");
    active.add(key);
    this.#propertyActive.set(value, active);
    try {
      return this.#propertyValue(value, key);
    } finally {
      active.delete(key);
    }
  }

  #propertyValue(value: SymbolicValue, key: string): SymbolicValue {
    if (value.kind === "external") {
      const path = [...value.path, key];
      if (
        this.#originCache === undefined &&
        ELECTRON_MODULE.test(path[0] ?? "") &&
        !this.#electronIdentity.intactExport(path)
      ) {
        return symbolicUnknown("overwritten Electron API member");
      }
      return { kind: "external", path };
    }
    if (value.kind === "record")
      return value.values.get(key) ?? symbolicUnknown("missing property");
    if (value.kind === "namespace") {
      if (
        this.#mutated.has(value.bindingId) ||
        this.#unsafeExports.has(`${value.bindingId}:${key}`)
      )
        return symbolicUnknown("ambiguous export writes");
      const replacement = this.#replacements.get(value.bindingId);
      if (replacement)
        return this.property(
          this.evaluate(replacement, value.environment),
          key,
        );
      const writes = (this.#writes.get(value.bindingId) ?? []).filter(
        (w) => w.path.length === 1 && w.path[0] === key,
      );
      const write = writes.at(-1);
      return write
        ? this.evaluate(write.value, value.environment)
        : symbolicUnknown("unresolved module export");
    }
    if (value.kind === "object") {
      let index = this.#literalPropertyIndex.get(value.node);
      if (index === undefined) {
        const properties = new Map<string, t.ObjectMethod | t.ObjectProperty>();
        index = properties;
        for (const property of value.node.properties) {
          const name = t.isSpreadElement(property)
            ? null
            : semanticStaticPropertyKey(property.key, property.computed);
          if (name === null || t.isSpreadElement(property)) {
            index = null;
            break;
          }
          properties.set(name, property);
        }
        this.#literalPropertyIndex.set(value.node, index);
      }
      if (index !== null) {
        const property = index.get(key);
        return property === undefined
          ? symbolicUnknown("missing property")
          : this.#objectPropertyValue(property, value.environment);
      }
      for (const p of [...value.node.properties].reverse()) {
        if (t.isSpreadElement(p)) {
          const spread = this.evaluate(p.argument, value.environment);
          const found = this.property(spread, key);
          if (found.kind !== "unknown") return found;
          if (
            this.unknownMembers(spread) > 0 ||
            this.members(spread).includes(key)
          )
            return found;
        } else if (semanticStaticPropertyKey(p.key, p.computed) === key) {
          return this.#objectPropertyValue(p, value.environment);
        } else if (semanticStaticPropertyKey(p.key, p.computed) === null)
          return symbolicUnknown("dynamic property overwrite");
      }
    }
    if (value.kind === "array" && /^\d+$/u.test(key))
      return value.values[Number(key)] ?? symbolicUnknown("missing argument");
    return symbolicUnknown("unresolved property");
  }

  #objectPropertyValue(
    property: t.ObjectMethod | t.ObjectProperty,
    environment: SymbolicEnvironment,
  ): SymbolicValue {
    return t.isObjectMethod(property) && property.kind !== "method"
      ? symbolicUnknown("accessor property")
      : this.evaluate(
          t.isObjectProperty(property) ? property.value : property,
          environment,
        );
  }

  members(
    value: SymbolicValue,
    active = new Set<SymbolicValue>(),
  ): readonly string[] {
    if (active.has(value)) return [];
    active.add(value);
    if (value.kind === "union")
      return [...new Set(value.values.flatMap((v) => this.members(v, active)))];
    if (value.kind === "record") return [...value.values.keys()];
    if (value.kind === "namespace") {
      const replacement = this.#replacements.get(value.bindingId);
      return replacement
        ? this.members(this.evaluate(replacement, value.environment), active)
        : [
            ...new Set(
              (this.#writes.get(value.bindingId) ?? []).flatMap((w) =>
                w.path.length === 1 && w.path[0] !== null ? [w.path[0]!] : [],
              ),
            ),
          ];
    }
    if (value.kind !== "object") return [];
    return [
      ...new Set(
        value.node.properties.flatMap((p) =>
          t.isSpreadElement(p)
            ? this.members(this.evaluate(p.argument, value.environment), active)
            : [semanticStaticPropertyKey(p.key, p.computed)].filter(
                (k): k is string => k !== null,
              ),
        ),
      ),
    ];
  }

  unknownMembers(
    value: SymbolicValue,
    active = new Set<SymbolicValue>(),
  ): number {
    if (active.has(value)) return 1;
    active.add(value);
    if (value.kind === "union")
      return value.values.reduce(
        (sum, v) => sum + this.unknownMembers(v, active),
        0,
      );
    if (value.kind === "record") return 0;
    if (value.kind === "namespace") {
      if (this.#mutated.has(value.bindingId)) return 1;
      const replacement = this.#replacements.get(value.bindingId);
      return replacement
        ? this.unknownMembers(
            this.evaluate(replacement, value.environment),
            active,
          )
        : 0;
    }
    if (value.kind !== "object") return 1;
    return value.node.properties.reduce(
      (sum, p) =>
        sum +
        (t.isSpreadElement(p)
          ? this.unknownMembers(
              this.evaluate(p.argument, value.environment),
              new Set(active),
            )
          : Number(semanticStaticPropertyKey(p.key, p.computed) === null)),
      0,
    );
  }

  bind(
    fn: SymbolicFunction,
    args: readonly SymbolicValue[],
    invocationNode?: t.Node,
  ): SymbolicEnvironment {
    const values = new Map<string, SymbolicValue>();
    fn.node.params.forEach((param, index) => {
      const target = t.isRestElement(param) ? param.argument : param;
      if (!t.isIdentifier(target)) return;
      const binding = resolveSemanticBindingState(
        this.state,
        target,
        target.name,
      );
      if (binding)
        values.set(
          binding.bindingId,
          t.isRestElement(param)
            ? { kind: "array", values: args.slice(index) }
            : (args[index] ?? symbolicUnknown("runtime parameter")),
        );
    });
    const scopeId =
      this.state.scopeByNode.get(fn.node)?.scopeId ??
      this.state.scopeByNode.get(fn.node.body)?.scopeId;
    return {
      values,
      parent: fn.environment,
      point: invocationNode ?? fn.node,
      scopeNode: fn.node,
      ...(scopeId === undefined ? {} : { scopeId }),
    };
  }

  arguments(
    node: t.CallExpression | t.OptionalCallExpression,
    env: SymbolicEnvironment,
  ): readonly SymbolicValue[] {
    return node.arguments.flatMap((a) => {
      if (!t.isSpreadElement(a)) return [this.evaluate(a, env)];
      const value = this.evaluate(a.argument, env);
      return value.kind === "array"
        ? value.values
        : [symbolicUnknown("dynamic spread arguments")];
    });
  }

  #evaluate(node: t.Node, env: SymbolicEnvironment): SymbolicValue {
    if (
      t.isStringLiteral(node) ||
      t.isNumericLiteral(node) ||
      t.isBooleanLiteral(node)
    )
      return { kind: "literal", value: node.value };
    if (t.isNullLiteral(node)) return { kind: "literal", value: null };
    if (t.isFunction(node))
      return { kind: "function", node, environment: env, origins: [] };
    if (t.isObjectExpression(node))
      return { kind: "object", node, environment: env };
    if (t.isIdentifier(node)) return this.#identifier(node, env);
    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      const key = semanticStaticPropertyKey(node.property, node.computed);
      if (key === null) return symbolicUnknown("dynamic member");
      const select = (): SymbolicValue =>
        this.property(this.evaluate(node.object, env), key);
      return this.#originCache === undefined
        ? select()
        : this.#atOriginPoint(node.object, select, true);
    }
    if (t.isSequenceExpression(node))
      return this.evaluate(node.expressions.at(-1), env);
    if (t.isAssignmentExpression(node)) return this.evaluate(node.right, env);
    if (t.isAwaitExpression(node)) return this.evaluate(node.argument, env);
    if (t.isUnaryExpression(node)) {
      const value = this.evaluate(node.argument, env);
      if (node.operator === "void")
        return { kind: "literal", value: undefined };
      const truth = symbolicTruth(value);
      if (node.operator === "!" && truth !== undefined)
        return { kind: "literal", value: !truth };
    }
    if (t.isConditionalExpression(node)) {
      const truth = symbolicTruth(this.evaluate(node.test, env));
      return truth === undefined
        ? symbolicUnion([
            symbolicCondition(this.evaluate(node.consequent, env), {
              node: node.test,
              positive: true,
            }),
            symbolicCondition(this.evaluate(node.alternate, env), {
              node: node.test,
              positive: false,
            }),
          ])
        : this.evaluate(truth ? node.consequent : node.alternate, env);
    }
    if (t.isLogicalExpression(node)) {
      const left = this.evaluate(node.left, env);
      const right = symbolicLogicalRight(node.operator, left);
      if (right !== undefined)
        return right ? this.evaluate(node.right, env) : left;
      const leftCondition: SymbolicCondition = {
        node: node.left,
        positive:
          node.operator === "&&"
            ? false
            : node.operator === "||"
              ? true
              : "not-nullish",
      };
      const rightCondition: SymbolicCondition = {
        node: node.left,
        positive:
          node.operator === "&&"
            ? true
            : node.operator === "||"
              ? false
              : "nullish",
      };
      return symbolicUnion([
        symbolicCondition(left, leftCondition),
        symbolicCondition(this.evaluate(node.right, env), rightCondition),
      ]);
    }
    if (t.isCallExpression(node) || t.isOptionalCallExpression(node))
      return this.#call(node, env);
    return symbolicUnknown(`unsupported ${node.type}`);
  }

  #identifier(node: t.Identifier, env: SymbolicEnvironment): SymbolicValue {
    const binding = resolveSemanticBindingState(this.state, node, node.name);
    if (
      !binding &&
      node.name === "undefined" &&
      !semanticResolutionBlocked(this.state, node, node.name)
    )
      return { kind: "literal", value: undefined };
    if (!binding)
      return !semanticResolutionBlocked(this.state, node, node.name) &&
        ["require", "navigator", "String", "Boolean"].includes(node.name)
        ? { kind: "external", path: [node.name] }
        : symbolicUnknown("unbound identifier");
    if (binding.definitions.some((d) => d.kind === "assignment"))
      return symbolicUnknown("reassigned binding");
    // Electron member identity is checked at the selected property. A write
    // to one method must not erase the module origin or unaffected siblings.
    const electronOrigin = this.#electronIdentity.exportPath(node);
    if (
      this.#originCache === undefined &&
      electronOrigin === undefined &&
      this.#mutated.has(binding.bindingId)
    )
      return symbolicUnknown("dynamic member writes");
    for (let e: SymbolicEnvironment | undefined = env; e; e = e.parent) {
      const value = e.values.get(binding.bindingId);
      if (value) return value;
    }
    if (
      this.#originCache === undefined &&
      electronOrigin === undefined &&
      this.#writes.has(binding.bindingId)
    )
      return symbolicUnknown("overwritten object members");
    const initializer =
      binding.initializers.length === 1 ? binding.initializers[0] : undefined;
    if (!initializer) {
      // Static imports have no initializer. During mutation discovery their
      // proven module origin comes from the shared identity owner.
      return this.#originCache !== undefined &&
        binding.initializers.length === 0 &&
        electronOrigin !== undefined
        ? { kind: "external", path: ["electron", ...electronOrigin] }
        : symbolicUnknown("missing or ambiguous initializer");
    }
    const point = this.#initializerReadPoint(binding.scopeId, env, node);
    if (
      !initializer.entryBody &&
      !binding.definitions.every(({ kind }) => kind === "function") &&
      (initializer.node.end == null ||
        point == null ||
        initializer.node.end > point)
    ) {
      this.unresolved = true;
      return symbolicUnknown("initializer not available at this read");
    }
    if (this.state.conditionalInitializers.has(initializer.node))
      return symbolicUnknown("conditional initializer");
    const select = (): SymbolicValue => {
      let value = this.evaluate(initializer.node, env);
      for (const key of initializer.projection) {
        if (key === null) return symbolicUnknown("dynamic destructuring");
        value = this.property(value, String(key));
      }
      return value;
    };
    const value =
      this.#originCache !== undefined && initializer.projection.length > 0
        ? this.#atOriginPoint(initializer.node, select, true)
        : select();
    return this.#originCache === undefined
      ? value
      : this.#originObject(value, binding, node, env);
  }

  #initializerReadPoint(
    bindingScopeId: string,
    environment: SymbolicEnvironment,
    readNode: t.Node,
  ): number | undefined {
    let current: SymbolicEnvironment | undefined = environment;
    let child: SymbolicEnvironment | undefined;
    while (current) {
      if (this.#scopeContains(bindingScopeId, current.scopeId)) {
        const point = child?.point ?? readNode;
        if (current.completedAt !== undefined)
          return current.completedAt.end ?? undefined;
        if (current.scopeNode && !this.#nodeWithin(point, current.scopeNode))
          return undefined;
        return point.start ?? undefined;
      }
      child = current;
      current = current.parent;
    }
    let outermost = environment;
    while (outermost.parent) outermost = outermost.parent;
    const point = outermost.point ?? environment.point ?? readNode;
    return point.start ?? undefined;
  }

  #scopeContains(bindingScopeId: string, environmentScopeId?: string): boolean {
    let scopeId: string | null = bindingScopeId;
    while (scopeId !== null) {
      if (scopeId === environmentScopeId) return true;
      scopeId = this.state.scopesById.get(scopeId)?.parentScopeId ?? null;
    }
    return false;
  }

  #nodeWithin(node: t.Node, ancestor?: t.Node): boolean {
    if (!ancestor) return false;
    let current: t.Node | undefined = node;
    while (current) {
      if (current === ancestor) return true;
      current = this.state.parentsByNode.get(current);
    }
    return false;
  }

  #completedEnvironment(
    environment: SymbolicEnvironment,
    activation: SymbolicEnvironment,
    returnPoint: t.Node,
  ): SymbolicEnvironment | undefined {
    if (environment === activation)
      return { ...environment, completedAt: returnPoint };
    if (environment.parent === undefined) return undefined;
    const parent = this.#completedEnvironment(
      environment.parent,
      activation,
      returnPoint,
    );
    return parent === undefined ? undefined : { ...environment, parent };
  }

  #completeReturnedFunction(
    value: SymbolicFunction,
    activation: SymbolicEnvironment,
    returnPoint: t.Node,
  ): SymbolicFunction {
    const environment = this.#completedEnvironment(
      value.environment,
      activation,
      returnPoint,
    );
    if (environment === undefined) return value;
    const { returnPoint: _returnPoint, ...returned } = value;
    return { ...returned, environment };
  }

  #moduleCompletionPoint(factory: t.Function): t.Node {
    let earliestReturn: t.ReturnStatement | undefined;
    const pending: t.Node[] = [factory.body];
    while (pending.length > 0) {
      const node = pending.pop();
      if (!node) continue;
      if (node !== factory.body && (t.isFunction(node) || t.isClass(node)))
        continue;
      if (
        t.isReturnStatement(node) &&
        (earliestReturn === undefined ||
          (node.start ?? Infinity) < (earliestReturn.start ?? Infinity))
      )
        earliestReturn = node;
      pending.push(...childNodes(node));
    }
    return earliestReturn ?? factory.body;
  }

  #call(
    node: t.CallExpression | t.OptionalCallExpression,
    env: SymbolicEnvironment,
  ): SymbolicValue {
    const callee = this.evaluate(node.callee, env);
    const args = this.arguments(node, env);
    return symbolicUnion(
      symbolicVariants(callee).map((value) => {
        let result: SymbolicValue;
        if (value.kind === "loader") {
          const key = args[0];
          const loaded =
            key?.kind === "literal"
              ? (value.modules.get(String(key.value)) ??
                symbolicUnknown("missing module"))
              : symbolicUnknown("dynamic module");
          if (loaded.kind === "namespace") {
            const factory = this.#namespaceOwners.get(loaded.bindingId);
            result =
              factory === undefined
                ? loaded
                : {
                    ...loaded,
                    environment: {
                      ...loaded.environment,
                      completedAt: this.#moduleCompletionPoint(factory),
                    },
                  };
          } else result = loaded;
        } else if (
          value.kind === "external" &&
          value.path.join(".") === "require"
        ) {
          const spec = args[0];
          result =
            spec?.kind === "literal" && typeof spec.value === "string"
              ? { kind: "external", path: [spec.value] }
              : symbolicUnknown("dynamic require");
        } else if (
          value.kind !== "function" ||
          this.#activeFunctions.has(value.node)
        ) {
          result = symbolicUnknown("unresolved or recursive call");
        } else {
          this.#activeFunctions.add(value.node);
          try {
            const bound = this.bind(value, args, node);
            const returned = t.isBlockStatement(value.node.body)
              ? this.#returns(value.node.body.body, bound)
              : this.evaluate(value.node.body, bound);
            result = symbolicUnion(
              symbolicVariants(returned).map((v) =>
                v.kind === "function"
                  ? {
                      ...this.#completeReturnedFunction(
                        v,
                        bound,
                        v.returnPoint ?? value.node.body,
                      ),
                      origins: [...value.origins, node, ...v.origins],
                    }
                  : v,
              ),
            );
          } finally {
            this.#activeFunctions.delete(value.node);
          }
        }
        for (const condition of value.conditions ?? [])
          result = symbolicCondition(result, condition);
        if (value.conditionUnresolved)
          result = symbolicConditionsUnresolved(result);
        return result;
      }),
    );
  }

  #returns(
    statements: readonly t.Statement[],
    env: SymbolicEnvironment,
  ): SymbolicValue {
    const flow = this.#returnFlow(statements, env);
    return symbolicUnion([
      ...flow.values,
      ...(flow.fallsThrough
        ? [{ kind: "literal" as const, value: undefined }]
        : []),
    ]);
  }

  #returnFlow(
    statements: readonly t.Statement[],
    env: SymbolicEnvironment,
    depth = 0,
  ): SymbolicReturnFlow {
    const possible: SymbolicValue[] = [];
    let unresolvedFallthrough = false;
    const continuationConditions: SymbolicCondition[] = [];
    const guardCurrentPath = (value: SymbolicValue): SymbolicValue => {
      let guarded = value;
      for (const condition of continuationConditions)
        guarded = symbolicCondition(guarded, condition);
      return unresolvedFallthrough
        ? symbolicConditionsUnresolved(guarded)
        : guarded;
    };
    for (const statement of statements) {
      if (--this.#remainingEvaluations < 0 || depth >= 128) {
        this.truncated = true;
        return {
          values: [...possible, symbolicUnknown("symbolic resource limit")],
          fallsThrough: false,
        };
      }
      if (t.isThrowStatement(statement))
        return {
          values: [...possible, symbolicUnknown("wrapper exits by throwing")],
          fallsThrough: false,
        };
      if (t.isReturnStatement(statement)) {
        const value = this.evaluate(statement.argument, env);
        const returned = symbolicUnion(
          symbolicVariants(value).map((variant) =>
            variant.kind === "function"
              ? { ...variant, returnPoint: statement }
              : variant,
          ),
        );
        return {
          values: [...possible, guardCurrentPath(returned)],
          fallsThrough: false,
        };
      }
      if (t.isBlockStatement(statement)) {
        const flow = this.#returnFlow(statement.body, env, depth + 1);
        possible.push(...flow.values.map(guardCurrentPath));
        if (!flow.fallsThrough)
          return { values: possible, fallsThrough: false };
      }
      if (t.isIfStatement(statement)) {
        const truth = symbolicTruth(this.evaluate(statement.test, env));
        const branches =
          truth === undefined
            ? [statement.consequent, statement.alternate]
            : [truth ? statement.consequent : statement.alternate];
        const flows = branches.map((branch) =>
          this.#returnFlow(branch ? [branch] : [], env, depth + 1),
        );
        possible.push(
          ...flows.flatMap((flow, index) =>
            flow.values.map((value) => {
              const guarded = guardCurrentPath(value);
              return truth === undefined
                ? symbolicCondition(guarded, {
                    node: statement.test,
                    positive: index === 0,
                  })
                : guarded;
            }),
          ),
        );
        if (flows.every((flow) => !flow.fallsThrough))
          return { values: possible, fallsThrough: false };
        if (truth === undefined) {
          const fallthrough = flows.flatMap((flow, index) =>
            flow.fallsThrough ? [{ flow, index }] : [],
          );
          if (
            fallthrough.length === 1 &&
            fallthrough[0]?.flow.values.length === 0
          )
            continuationConditions.push({
              node: statement.test,
              positive: fallthrough[0].index === 0,
            });
          else if (
            fallthrough.length > 0 &&
            (fallthrough.length < flows.length ||
              fallthrough.some(({ flow }) => flow.values.length > 0))
          )
            unresolvedFallthrough = true;
        }
      }
    }
    return { values: possible, fallsThrough: true };
  }

  #indexBootstrap(call: t.CallExpression): void {
    const bootstrap = javascriptBootstrapAt(call, this.state);
    if (!bootstrap) return;
    const modules = new Map<string, SymbolicValue>();
    const tableAliases = new Set([bootstrap.tableBindingId]);
    const pendingAliases = [bootstrap.tableBindingId];
    while (pendingAliases.length > 0) {
      const source = pendingAliases.pop()!;
      for (const alias of this.#aliasesByBinding.get(source) ?? [])
        if (!tableAliases.has(alias)) {
          tableAliases.add(alias);
          pendingAliases.push(alias);
        }
    }
    for (const property of bootstrap.table.properties) {
      const factory = moduleFactory(property);
      if (!factory) continue;
      const moduleKey = modulePropertyName(property);
      const values = new Map<string, SymbolicValue>();
      const environment: SymbolicEnvironment = {
        values,
        point: factory.body,
        scopeNode: factory,
        ...(this.state.scopeByNode.get(factory)?.scopeId === undefined
          ? {}
          : { scopeId: this.state.scopeByNode.get(factory)!.scopeId }),
      };
      const first = factory.params[0];
      const second = factory.params[1];
      const third = factory.params[2];
      const binding = (n: t.Node | undefined) =>
        t.isIdentifier(n)
          ? resolveSemanticBindingState(this.state, n, n.name)?.bindingId
          : undefined;
      const moduleId = binding(first);
      const exportsId = binding(second);
      const loaderId = binding(third);
      const namespaceId = `${String(factory.start)}:exports`;
      this.#namespaceOwners.set(namespaceId, factory);
      const namespace: SymbolicValue = {
        kind: "namespace",
        bindingId: namespaceId,
        environment,
      };
      if (moduleId) {
        values.set(moduleId, {
          kind: "record",
          values: new Map([["exports", namespace]]),
        });
        this.#exportAliases.set(moduleId, namespaceId);
        this.#moduleBindings.add(moduleId);
      }
      if (exportsId) {
        values.set(exportsId, namespace);
        this.#exportAliases.set(exportsId, namespaceId);
      }
      if (loaderId) values.set(loaderId, { kind: "loader", modules });
      this.#environments.set(factory, environment);
      modules.set(moduleKey, namespace);
    }
    this.#bootstrapTables.push({ tableAliases, modules });
  }

  #indexBindingAliases(): void {
    for (const binding of this.state.bindingsById.values()) {
      const initializer = binding.initializers[0];
      if (
        !initializer ||
        initializer.entryBody !== undefined ||
        initializer.projection.length !== 0 ||
        !t.isIdentifier(initializer.node)
      )
        continue;
      const source = resolveSemanticBindingState(
        this.state,
        initializer.node,
        initializer.node.name,
      );
      if (!source) continue;
      const aliases = this.#aliasesByBinding.get(source.bindingId) ?? [];
      aliases.push(binding.bindingId);
      this.#aliasesByBinding.set(source.bindingId, aliases);
    }
  }

  #atOriginPoint<Value>(
    point: t.Node,
    read: () => Value,
    after = false,
  ): Value {
    const cache = this.#originCache;
    const previous = this.#originPoint;
    const previousAfter = this.#originPointAfter;
    this.#originCache = new WeakMap();
    this.#originPoint = point;
    this.#originPointAfter = after;
    try {
      return read();
    } finally {
      this.#originCache = cache;
      this.#originPoint = previous;
      this.#originPointAfter = previousAfter;
    }
  }

  #functionOwner(node: t.Node): t.Node | undefined {
    let current: t.Node | undefined = node;
    while (current && !t.isFunction(current) && !t.isProgram(current))
      current = this.state.parentsByNode.get(current);
    return current;
  }

  // Slot reads capture values; object references retain the indexed writes to
  // that exact object, even after a container stops pointing to it.
  #originObject(
    value: SymbolicValue,
    binding: JavaScriptSemanticBindingState,
    node: t.Identifier,
    environment: SymbolicEnvironment,
  ): SymbolicValue {
    return symbolicUnion(
      symbolicVariants(value).map((variant) => {
        if (
          variant.kind !== "object" &&
          variant.kind !== "record" &&
          variant.kind !== "array"
        )
          return variant;
        this.#retainOriginReference(variant, {
          binding,
          node,
          environment,
          path: [],
        });
        return this.#originReferenceValue(variant);
      }),
    );
  }

  #references(value: OriginObjectValue): OriginReference[] {
    if (value.kind !== "object") {
      let references = this.#originCollectionReferences.get(value.values);
      if (!references) {
        references = [];
        this.#originCollectionReferences.set(value.values, references);
      }
      return references;
    }
    let objects = this.#originReferences.get(value.environment);
    if (!objects) {
      objects = new WeakMap();
      this.#originReferences.set(value.environment, objects);
    }
    let references = objects.get(value.node);
    if (!references) {
      references = [];
      objects.set(value.node, references);
    }
    return references;
  }

  #retainOriginReference(
    value: OriginObjectValue,
    reference: OriginReference,
  ): void {
    if (--this.#remainingEvaluations < 0) {
      this.truncated = true;
      return;
    }
    const references = this.#references(value);
    if (
      !references.some(
        (existing) =>
          existing.binding === reference.binding &&
          existing.environment === reference.environment &&
          existing.path.length === reference.path.length &&
          existing.path.every((key, index) => key === reference.path[index]),
      )
    )
      references.push(reference);
  }

  #originReferenceWrites(
    value: OriginObjectValue,
    reference: OriginReference,
  ): readonly OriginPropertyWrite[] {
    const target = this.#originPoint ?? reference.node;
    const read =
      this.#functionOwner(target) === this.#functionOwner(reference.node)
        ? target
        : reference.node;
    const start = this.#initializerReadPoint(
      reference.binding.scopeId,
      reference.environment,
      read,
    );
    const point =
      this.#originPointAfter && read === target && start === target.start
        ? (target.end ?? undefined)
        : start;
    if (point === undefined) return [];
    const writes = this.#originWrites(
      reference.binding.bindingId,
      point,
      this.#functionOwner(read),
      reference.environment,
    );
    if (reference.path.length === 0) return writes;
    const projected: OriginPropertyWrite[] = [];
    for (const write of writes) {
      if (
        write.path.length <= reference.path.length ||
        !reference.path.every(
          (key, index) =>
            write.path[index] === null || write.path[index] === key,
        )
      )
        continue;
      // A later replacement of an ancestor slot must not retarget a captured
      // reference. Compare the selected object before this write commits.
      const matches = this.#atOriginPoint(write.source.site, () => {
        let selected = this.evaluate(reference.node, reference.environment);
        for (const key of reference.path)
          selected = this.property(selected, key);
        return symbolicVariants(selected).some((candidate) =>
          value.kind === "object"
            ? candidate.kind === "object" &&
              candidate.node === value.node &&
              candidate.environment === value.environment
            : candidate.kind === value.kind &&
              candidate.values === value.values,
        );
      });
      if (matches)
        projected.push({
          ...write,
          path: write.path.slice(reference.path.length),
          definite:
            write.definite &&
            write.path
              .slice(0, reference.path.length)
              .every((key) => key !== null),
        });
    }
    return projected;
  }

  #originReferenceValue(value: OriginObjectValue): SymbolicValue {
    const snapshot = (value as OriginValue)[originSnapshot];
    if (snapshot?.reference) return value;
    const references = this.#references(value);
    const resolver = this;
    return {
      ...value,
      [originSnapshot]: {
        reference: true,
        base: snapshot?.base ?? value,
        get writes(): readonly OriginPropertyWrite[] {
          const merged = [...(snapshot?.writes.slice(0, snapshot.end) ?? [])];
          for (const reference of [...references])
            for (const write of resolver.#originReferenceWrites(
              value,
              reference,
            ))
              merged.push(write);
          const seen = new Set<PropertyWrite>();
          return merged
            .filter(
              ({ source }) => !seen.has(source) && Boolean(seen.add(source)),
            )
            .sort(
              (left, right) =>
                (left.source.site.end ?? 0) - (right.source.site.end ?? 0) ||
                (right.source.site.start ?? 0) - (left.source.site.start ?? 0),
            );
        },
      },
    } as OriginValue;
  }

  #originWrites(
    bindingId: string,
    point: number,
    owner: t.Node | undefined,
    environment: SymbolicEnvironment,
  ): readonly OriginPropertyWrite[] {
    const pending = [bindingId];
    const bindings = new Set<string>();
    const writes: OriginPropertyWrite[] = [];
    while (pending.length > 0) {
      if (--this.#remainingEvaluations < 0) {
        this.truncated = true;
        break;
      }
      const id = pending.pop()!;
      if (bindings.has(id)) continue;
      bindings.add(id);
      for (const alias of this.#aliasesByBinding.get(id) ?? []) {
        const candidate = this.state.bindingsById.get(alias);
        const initializer = candidate?.initializers[0];
        if (
          candidate &&
          initializer &&
          candidate.initializers.length === 1 &&
          candidate.definitions.every(({ kind }) => kind !== "assignment") &&
          !this.state.conditionalInitializers.has(initializer.node) &&
          (initializer.node.end ?? Infinity) <= point
        )
          pending.push(alias);
      }
      for (const write of this.#writes.get(id) ?? []) {
        if (
          write.path.length === 0 ||
          (write.site.end ?? Infinity) > point ||
          this.#functionOwner(write.site) !== owner
        )
          continue;
        if (--this.#remainingEvaluations < 0) {
          this.truncated = true;
          break;
        }
        let definite = true;
        for (
          let parent = this.state.parentsByNode.get(write.site);
          parent && parent !== owner;
          parent = this.state.parentsByNode.get(parent)
        ) {
          if (
            t.isIfStatement(parent) ||
            t.isConditionalExpression(parent) ||
            t.isLogicalExpression(parent) ||
            t.isLoop(parent) ||
            t.isSwitchCase(parent) ||
            t.isTryStatement(parent)
          )
            definite = false;
        }
        const assignment = t.isAssignmentExpression(write.site);
        const logical =
          assignment && ["&&=", "||=", "??="].includes(write.site.operator);
        const plain = assignment
          ? write.site.operator === "=" || logical
          : t.isCallExpression(write.site);
        if (logical) definite = false;
        let retainedValue: SymbolicValue | undefined;
        const readValue = (): SymbolicValue =>
          plain
            ? this.#atOriginPoint(write.site, () =>
                this.evaluate(write.value, environment),
              )
            : symbolicUnknown("non-value property write");
        writes.push({
          source: write,
          path: write.path,
          definite,
          get value(): SymbolicValue {
            return (retainedValue ??= readValue());
          },
        });
      }
    }
    return writes;
  }

  /** Possible selected values for mutation provenance, never exact read proof. */
  #originProperties(
    value: SymbolicValue,
    key: string | null,
    excluded: ReadonlySet<string> = new Set(),
    active = new Set<SymbolicValue>(),
  ): OriginProperties {
    const result = this.#readOriginProperties(value, key, excluded, active);
    if (
      (value.kind !== "object" &&
        value.kind !== "record" &&
        value.kind !== "array") ||
      key === null
    )
      return result;
    const references = [...this.#references(value)];
    return {
      ...result,
      values: result.values.map((member) => {
        if (
          member.kind !== "object" &&
          member.kind !== "record" &&
          member.kind !== "array"
        )
          return member;
        for (const reference of references)
          this.#retainOriginReference(member, {
            ...reference,
            path: [...reference.path, key],
          });
        return this.#originReferenceValue(member);
      }),
    };
  }

  #readOriginProperties(
    value: SymbolicValue,
    key: string | null,
    excluded: ReadonlySet<string> = new Set(),
    active = new Set<SymbolicValue>(),
  ): OriginProperties {
    const values: SymbolicValue[] = [];
    const definiteKeys = new Set<string>();
    const empty = { values, definiteKeys };
    if (--this.#remainingEvaluations < 0 || active.size >= 128) {
      this.truncated = true;
      return empty;
    }
    if (active.has(value) || (key !== null && excluded.has(key))) return empty;
    const visiting = new Set(active).add(value);
    const snapshot = (value as OriginValue)[originSnapshot];
    if (snapshot)
      return this.#originSnapshotProperties(snapshot, key, excluded, visiting);
    if (value.kind === "union") {
      let common: Set<string> | undefined;
      for (const variant of value.values) {
        const result = this.#originProperties(variant, key, excluded, visiting);
        for (const member of result.values) values.push(member);
        common =
          common === undefined
            ? new Set(result.definiteKeys)
            : new Set(
                [...common].filter((name) => result.definiteKeys.has(name)),
              );
      }
      return { values, definiteKeys: common ?? definiteKeys };
    }
    if (value.kind === "object") {
      const covered = new Set(excluded);
      for (
        let index = value.node.properties.length - 1;
        index >= 0;
        index -= 1
      ) {
        if (--this.#remainingEvaluations < 0) {
          this.truncated = true;
          break;
        }
        if (key !== null && covered.has(key)) break;
        const property = value.node.properties[index]!;
        if (t.isSpreadElement(property)) {
          const result = this.#atOriginPoint(property, () => {
            const spread = this.evaluate(property.argument, value.environment);
            return this.#originProperties(spread, key, covered, visiting);
          });
          for (const member of result.values) values.push(member);
          for (const name of result.definiteKeys) {
            covered.add(name);
            definiteKeys.add(name);
          }
          continue;
        }
        const name = semanticStaticPropertyKey(property.key, property.computed);
        if (name === null) {
          // An unknown key can replace a known property or introduce another
          // one; it cannot prove that an earlier possible value was removed.
          values.push(this.#objectPropertyValue(property, value.environment));
        } else {
          if (!covered.has(name) && (key === null || key === name))
            values.push(this.#objectPropertyValue(property, value.environment));
          covered.add(name);
          definiteKeys.add(name);
        }
      }
      return { values, definiteKeys };
    }
    if (value.kind === "namespace") {
      if (this.#mutated.has(value.bindingId)) return empty;
      const replacement = this.#replacements.get(value.bindingId);
      if (replacement)
        return this.#originProperties(
          this.evaluate(replacement, value.environment),
          key,
          excluded,
          visiting,
        );
      for (const name of this.members(value)) {
        if (--this.#remainingEvaluations < 0) {
          this.truncated = true;
          break;
        }
        if (this.#unsafeExports.has(`${value.bindingId}:${name}`)) continue;
        definiteKeys.add(name);
        if (!excluded.has(name) && (key === null || key === name))
          values.push(this.#propertyValue(value, name));
      }
      return { values, definiteKeys };
    }
    if (value.kind === "record" || value.kind === "array") {
      const entries = value.values.entries();
      for (const [rawName, member] of entries) {
        const name = String(rawName);
        if (--this.#remainingEvaluations < 0) {
          this.truncated = true;
          break;
        }
        definiteKeys.add(name);
        if (!excluded.has(name) && (key === null || key === name))
          values.push(member);
      }
      return { values, definiteKeys };
    }
    // A known external key is a possible member, but not proof of an own
    // enumerable key when the value is copied by an object spread.
    if (key !== null) values.push(this.#propertyValue(value, key));
    return { values, definiteKeys };
  }

  #originSnapshotProperties(
    snapshot: NonNullable<OriginValue[typeof originSnapshot]>,
    key: string | null,
    excluded: ReadonlySet<string>,
    active: Set<SymbolicValue>,
  ): OriginProperties {
    const writes = snapshot.writes;
    let end = snapshot.end ?? writes.length;
    let write = writes[end - 1];
    while (write !== undefined) {
      if (--this.#remainingEvaluations < 0) {
        this.truncated = true;
        return { values: [], definiteKeys: new Set() };
      }
      const head = write.path[0];
      if (
        head === null ||
        (!excluded.has(head!) && (key === null || head === key))
      )
        break;
      end -= 1;
      write = writes[end - 1];
    }
    if (!write)
      return this.#originProperties(snapshot.base, key, excluded, active);
    const prior: OriginValue = {
      ...snapshot.base,
      [originSnapshot]: { base: snapshot.base, writes, end: end - 1 },
    };
    const head = write.path[0];
    const blocked = new Set(excluded);
    if (head !== null && write.definite) blocked.add(head!);
    if (write.path.length === 1) {
      const earlier = this.#originProperties(prior, key, blocked, active);
      const removed = t.isUnaryExpression(write.source.site, {
        operator: "delete",
      });
      const definiteKeys = new Set(earlier.definiteKeys);
      if (head !== null) {
        if (removed) definiteKeys.delete(head!);
        else if (write.definite) definiteKeys.add(head!);
      } else if (removed) definiteKeys.clear();
      return {
        values: removed ? earlier.values : [...earlier.values, write.value],
        definiteKeys,
      };
    }
    const selected = head ?? key;
    const parents = this.#originProperties(prior, selected, excluded, active);
    const values = parents.values.map((parent): OriginValue => ({
      ...parent,
      [originSnapshot]: {
        base: parent,
        writes: [
          {
            ...write,
            path: write.path.slice(1),
            definite: write.definite && head !== null,
          },
        ],
      },
    }));
    const siblings =
      head !== null && key === null
        ? this.#originProperties(
            prior,
            null,
            new Set([...excluded, head!]),
            active,
          )
        : { values: [], definiteKeys: new Set<string>() };
    return {
      values: [...values, ...siblings.values],
      definiteKeys: new Set([
        ...parents.definiteKeys,
        ...siblings.definiteKeys,
      ]),
    };
  }

  #symbolicElectronWritePaths(
    target: t.Node,
  ): readonly (readonly (string | null)[])[] {
    const { root, members } = electronMemberPath(target);
    let values = [this.evaluate(root)];
    const paths: (readonly (string | null)[])[] = [];
    for (
      let offset = 0;
      offset <= members.length && values.length > 0;
      offset += 1
    ) {
      const next: SymbolicValue[] = [];
      for (const value of values.flatMap(symbolicVariants)) {
        if (--this.#remainingEvaluations < 0) {
          this.truncated = true;
          return [["electron"]];
        }
        if (
          value.kind === "external" &&
          ELECTRON_MODULE.test(value.path[0] ?? "")
        )
          paths.push([
            "electron",
            ...electronExportPath(value.path.slice(1)),
            ...members.slice(offset),
          ]);
        else if (offset < members.length)
          for (const member of this.#originProperties(
            value,
            members[offset] ?? null,
          ).values)
            next.push(member);
      }
      values = next;
    }
    return paths;
  }

  #invalidateBootstrapTable(
    tableAliases: ReadonlySet<string>,
    modules: Map<string, SymbolicValue>,
  ): void {
    let invalidateAll = false;
    const invalidSlots = new Set<string>();
    for (const bindingId of tableAliases) {
      if (this.#mutated.has(bindingId)) invalidateAll = true;
      for (const definition of this.state.bindingsById.get(bindingId)
        ?.definitions ?? [])
        if (definition.kind === "assignment") invalidateAll = true;
      for (const write of this.#writes.get(bindingId) ?? []) {
        if (write.path.length === 0 || write.path[0] === null)
          invalidateAll = true;
        else invalidSlots.add(write.path[0]!);
      }
    }
    if (invalidateAll) modules.clear();
    else for (const key of invalidSlots) modules.delete(key);
  }

  #indexWrite(target: t.Node, value: t.Node, site: t.Node): void {
    const { root, members: path } = electronMemberPath(target);
    if (path.includes(null) && t.isIdentifier(root)) {
      const binding = resolveSemanticBindingState(this.state, root, root.name);
      if (binding)
        this.#mutated.add(
          this.#exportAliases.get(binding.bindingId) ?? binding.bindingId,
        );
    }
    if (t.isIdentifier(root)) this.#addWrite(root, path, value, site);
  }

  #addWrite(
    root: t.Identifier,
    path: readonly (string | null)[],
    value: t.Node,
    site: t.Node,
  ): void {
    const binding = resolveSemanticBindingState(this.state, root, root.name);
    if (!binding) return;
    const alias = this.#exportAliases.get(binding.bindingId);
    if (this.#moduleBindings.has(binding.bindingId) && path[0] !== "exports")
      return;
    const key = alias ?? binding.bindingId;
    const selected = this.#moduleBindings.has(binding.bindingId)
      ? path.slice(1)
      : path;
    if (alias) {
      const owner = this.#namespaceOwners.get(alias);
      for (
        let parent = this.state.parentsByNode.get(site);
        parent && parent !== owner;
        parent = this.state.parentsByNode.get(parent)
      ) {
        if (
          t.isFunction(parent) ||
          t.isIfStatement(parent) ||
          t.isConditionalExpression(parent) ||
          t.isLogicalExpression(parent) ||
          t.isLoop(parent) ||
          t.isSwitchCase(parent) ||
          t.isTryStatement(parent)
        ) {
          if (selected.length === 0) this.#mutated.add(key);
          else this.#unsafeExports.add(`${key}:${selected[0] ?? ""}`);
          return;
        }
      }
    }
    if (alias && selected.length === 0) {
      this.#replacements.set(key, value);
      return;
    }
    const writes = this.#writes.get(key) ?? [];
    writes.push({ path: selected, value, site });
    this.#writes.set(key, writes);
  }
}
