import { beforeAll, describe, expect, it } from "vitest";

import { Tensor, DType } from "../core/tensor";
import { Device, Runtime } from "../core/runtime";
import { Buffer, Module, Parameter } from "./module";
import {
  ModuleDict,
  ModuleList,
  ParameterDict,
  ParameterList,
  Sequential,
} from "./containers";

class AddScalarModule extends Module {
  constructor(private readonly delta: number) {
    super();
  }

  forward(input: Tensor): Tensor {
    return input.add(this.delta);
  }
}

class ParamCarrierModule extends Module {
  public p = new Parameter(new Tensor([1, 2]));
  public b = new Buffer(new Tensor([9]));

  constructor() {
    super();
    this.registerParameter("p", this.p);
    this.registerBuffer("b", this.b);
  }

  attach(name: string, module: Module): this {
    this.registerModule(name, module);
    return this;
  }

  detachModule(name: string): this {
    this.registerModule(name, null);
    return this;
  }

  detachParam(name: string): this {
    this.registerParameter(name, null);
    return this;
  }

  detachBuffer(name: string): this {
    this.registerBuffer(name, null);
    return this;
  }

  forward(input: Tensor): Tensor {
    return input;
  }
}

class ExtraReprModule extends Module {
  constructor(private readonly inFeatures: number, private readonly outFeatures: number) {
    super();
  }

  forward(input: Tensor): Tensor {
    return input;
  }

  extraRepr(): string {
    return `in_features=${this.inFeatures}, out_features=${this.outFeatures}`;
  }
}

class NonPersistentBufferModule extends Module {
  public nb = new Buffer(new Tensor([42]), false);

  constructor() {
    super();
    this.registerBuffer("nb", this.nb);
  }

  forward(input: Tensor): Tensor {
    return input;
  }
}

describe("nn module/container basics", () => {
  beforeAll(async () => {
    if (typeof (globalThis as any).GPUBuffer === "undefined") {
      (globalThis as any).GPUBuffer = class GPUBufferShim {};
    }
    await Runtime.initialize({
      devices: [Device.cpu()],
      defaultDevice: Device.cpu(),
    });
  });

  // ====== Sequential ======

  it("Sequential composes modules in order", async () => {
    const seq = new Sequential(new AddScalarModule(1), new AddScalarModule(2));
    const output = seq.forward(new Tensor([1, 2, 3])) as Tensor;

    expect(await output.toArray()).toEqual([4, 5, 6]);

    seq.append(new AddScalarModule(1));
    expect(seq.length).toBe(3);
    expect(seq.pop()).toBeInstanceOf(AddScalarModule);
    expect(seq.length).toBe(2);
  });

  it("Sequential.insert inserts module at the given index", async () => {
    const seq = new Sequential(new AddScalarModule(10), new AddScalarModule(20));
    seq.insert(1, new AddScalarModule(5));
    expect(seq.length).toBe(3);
    const out = seq.forward(new Tensor([0])) as Tensor;
    // 0 + 10 + 5 + 20 = 35
    expect(await out.toArray()).toEqual([35]);
  });

  it("Sequential.get returns the module at the given index", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const seq = new Sequential(m1, m2);
    expect(seq.get(0)).toBe(m1);
    expect(seq.get(1)).toBe(m2);
  });

  it("Sequential is iterable", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const seq = new Sequential(m1, m2);
    const collected = [...seq];
    expect(collected).toEqual([m1, m2]);
  });

  it("Sequential.pop throws when empty", () => {
    const seq = new Sequential();
    expect(() => seq.pop()).toThrow(/empty/i);
  });

  // ====== ModuleList ======

  it("ModuleList supports append and negative indexing", () => {
    const list = new ModuleList([new AddScalarModule(1)]);

    list.append(new AddScalarModule(2));
    expect(list.length).toBe(2);
    expect(list.get(-1)).toBeInstanceOf(AddScalarModule);
    expect(() => list.forward(new Tensor([1]))).toThrow(
      /does not implement forward/i
    );
  });

  it("ModuleList.extend adds multiple modules", () => {
    const list = new ModuleList();
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    list.extend([m1, m2]);
    expect(list.length).toBe(2);
    expect(list.get(0)).toBe(m1);
    expect(list.get(1)).toBe(m2);
  });

  it("ModuleList.insert places module at the correct index", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const m3 = new AddScalarModule(3);
    const list = new ModuleList([m1, m3]);
    list.insert(1, m2);
    expect(list.length).toBe(3);
    expect(list.get(1)).toBe(m2);
  });

  it("ModuleList.set replaces module at index (including negative)", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const replacement = new AddScalarModule(99);
    const list = new ModuleList([m1, m2]);
    list.set(-1, replacement);
    expect(list.get(1)).toBe(replacement);
    list.set(0, replacement);
    expect(list.get(0)).toBe(replacement);
  });

  it("ModuleList.slice returns a subset of modules", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const m3 = new AddScalarModule(3);
    const list = new ModuleList([m1, m2, m3]);
    const sliced = list.slice(1, 3);
    expect(sliced).toEqual([m2, m3]);
  });

  it("ModuleList.pop removes and returns the last module", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const list = new ModuleList([m1, m2]);
    const popped = list.pop();
    expect(popped).toBe(m2);
    expect(list.length).toBe(1);
  });

  it("ModuleList.pop throws when empty", () => {
    const list = new ModuleList();
    expect(() => list.pop()).toThrow(/empty/i);
  });

  it("ModuleList is iterable", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const list = new ModuleList([m1, m2]);
    const collected = [...list];
    expect(collected).toEqual([m1, m2]);
  });

  it("ModuleList created without arguments has zero length", () => {
    const list = new ModuleList();
    expect(list.length).toBe(0);
  });

  // ====== Module Hooks ======

  it("Module hooks can transform input and output through call()", async () => {
    const mod = new AddScalarModule(1);
    mod.registerForwardPreHook((_module, inputs) => [inputs[0].add(1)]);
    mod.registerForwardHook((_module, _inputs, output) => output.mul(2));

    const out = (await mod.call(new Tensor([1]))) as Tensor;
    expect(await out.toArray()).toEqual([6]); // ((1 + 1) + 1) * 2
  });

  it("removing a hook stops further output modification", async () => {
    const mod = new AddScalarModule(1);
    const handle = mod.registerForwardHook((_module, _inputs, output) =>
      output.mul(10)
    );

    const beforeRemove = (await mod.call(new Tensor([1]))) as Tensor;
    expect(await beforeRemove.toArray()).toEqual([20]);

    handle.remove();
    const afterRemove = (await mod.call(new Tensor([1]))) as Tensor;
    expect(await afterRemove.toArray()).toEqual([2]);
  });

  it("registerBackwardHook returns a handle with remove()", () => {
    const mod = new AddScalarModule(1);
    const handle = mod.registerBackwardHook(
      (_module, _gradInput, _gradOutput) => undefined
    );
    expect(handle.id).toBeDefined();
    expect(typeof handle.remove).toBe("function");
    handle.remove(); // should not throw
  });

  it("call() works without hooks and returns realized output", async () => {
    const mod = new AddScalarModule(5);
    const out = (await mod.call(new Tensor([10]))) as Tensor;
    expect(await out.toArray()).toEqual([15]);
  });

  // ====== Training Mode ======

  it("train()/eval() propagate to nested modules", () => {
    const childA = new AddScalarModule(1);
    const childB = new AddScalarModule(2);
    const seq = new Sequential(childA, childB);

    seq.eval();
    expect(seq.training).toBe(false);
    expect((seq.get(0) as AddScalarModule).training).toBe(false);
    expect((seq.get(1) as AddScalarModule).training).toBe(false);

    seq.train(true);
    expect(seq.training).toBe(true);
    expect((seq.get(0) as AddScalarModule).training).toBe(true);
  });

  // ====== State Dict ======

  it("stateDict() includes parameters and persistent buffers", () => {
    const root = new ParamCarrierModule().attach(
      "child",
      new ParamCarrierModule()
    );
    const state = root.stateDict();

    expect(state.has("p")).toBe(true);
    expect(state.has("b")).toBe(true);
    expect(state.has("child.p")).toBe(true);
    expect(state.has("child.b")).toBe(true);
  });

  it("stateDict() excludes non-persistent buffers", () => {
    const mod = new NonPersistentBufferModule();
    const state = mod.stateDict();
    expect(state.has("nb")).toBe(false);
  });

  it("loadStateDict(strict=false) reports missing/unexpected keys without throwing", async () => {
    const mod = new ParamCarrierModule();
    const good = new Tensor([7, 8]);
    const result = mod.loadStateDict(
      new Map<string, Tensor>([
        ["p", good],
        ["extra", new Tensor([1])],
      ]),
      false
    );

    expect(result.missing).toContain("b");
    expect(result.unexpected).toContain("extra");
    expect(await mod.p.data.toArray()).toEqual([7, 8]);
  });

  it("loadStateDict(strict=true) throws on missing or unexpected keys", () => {
    const mod = new ParamCarrierModule();
    expect(() =>
      mod.loadStateDict(
        new Map<string, Tensor>([["extra", new Tensor([1])]]),
        true
      )
    ).toThrow(/missing keys|unexpected keys/i);
  });

  it.each([
    {
      name: "exact match strict=true succeeds with no diffs",
      strict: true,
      entries: [
        ["p", [11, 12]],
        ["b", [13]],
      ] as [string, number[]][],
      expectThrow: false,
      missing: [] as string[],
      unexpected: [] as string[],
      expectedP: [11, 12],
    },
    {
      name: "missing buffer strict=false reports missing",
      strict: false,
      entries: [["p", [21, 22]]] as [string, number[]][],
      expectThrow: false,
      missing: ["b"],
      unexpected: [],
      expectedP: [21, 22],
    },
    {
      name: "unexpected key strict=false reports unexpected",
      strict: false,
      entries: [
        ["p", [31, 32]],
        ["b", [33]],
        ["ghost", [34]],
      ] as [string, number[]][],
      expectThrow: false,
      missing: [],
      unexpected: ["ghost"],
      expectedP: [31, 32],
    },
    {
      name: "missing parameter strict=true throws",
      strict: true,
      entries: [["b", [41]]] as [string, number[]][],
      expectThrow: true,
      missing: ["p"],
      unexpected: [],
      expectedP: [1, 2],
    },
  ])("loadStateDict table-driven: $name", async (tc) => {
    const mod = new ParamCarrierModule();
    const state = new Map<string, Tensor>(
      tc.entries.map(([name, data]) => [name, new Tensor(data)])
    );

    if (tc.expectThrow) {
      expect(() => mod.loadStateDict(state, tc.strict)).toThrow();
      expect(await mod.p.data.toArray()).toEqual(tc.expectedP);
      return;
    }

    const result = mod.loadStateDict(state, tc.strict);
    expect(result.missing.sort()).toEqual([...tc.missing].sort());
    expect(result.unexpected.sort()).toEqual([...tc.unexpected].sort());
    expect(await mod.p.data.toArray()).toEqual(tc.expectedP);
  });

  // ====== Parameter / Buffer Access ======

  it("getParameter/getBuffer/getSubmodule resolve nested names", () => {
    const child = new ParamCarrierModule();
    const root = new ParamCarrierModule().attach("child", child);

    expect(root.getParameter("child.p")).toBeDefined();
    expect(root.getBuffer("child.b")).toBeDefined();
    expect(root.getSubmodule("child")).toBe(child);
    expect(root.getParameter("missing")).toBeUndefined();
  });

  it("getParameter returns undefined for non-existent nested param", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    expect(root.getParameter("nonexistent.p")).toBeUndefined();
    expect(root.getParameter("p")).toBeDefined();
  });

  it("getBuffer returns undefined for non-existent nested buffer", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    expect(root.getBuffer("nonexistent.b")).toBeUndefined();
    expect(root.getBuffer("b")).toBeDefined();
  });

  it("getSubmodule returns undefined for non-existent submodule path", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    expect(root.getSubmodule("missing")).toBeUndefined();
    expect(root.getSubmodule("child")).toBeDefined();
  });

  // ====== Register null (deletion) ======

  it("registerParameter(null) removes the parameter", () => {
    const mod = new ParamCarrierModule();
    expect(mod.getParameter("p")).toBeDefined();
    mod.detachParam("p");
    expect(mod.getParameter("p")).toBeUndefined();
  });

  it("registerBuffer(null) removes the buffer", () => {
    const mod = new ParamCarrierModule();
    expect(mod.getBuffer("b")).toBeDefined();
    mod.detachBuffer("b");
    expect(mod.getBuffer("b")).toBeUndefined();
  });

  it("registerModule(null) removes the module", () => {
    const mod = new ParamCarrierModule().attach("child", new AddScalarModule(1));
    expect(mod.getSubmodule("child")).toBeDefined();
    mod.detachModule("child");
    expect(mod.getSubmodule("child")).toBeUndefined();
  });

  // ====== Generators ======

  it("parameters() yields own and child params with recurse=true", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const params = [...root.parameters(true)];
    expect(params.length).toBe(2); // root.p + child.p
  });

  it("parameters(recurse=false) yields only own params", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const params = [...root.parameters(false)];
    expect(params.length).toBe(1);
  });

  it("namedParameters() yields prefixed names recursively", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const named = [...root.namedParameters()];
    const names = named.map(([name]) => name);
    expect(names).toContain("p");
    expect(names).toContain("child.p");
  });

  it("namedParameters(prefix) prepends the prefix", () => {
    const mod = new ParamCarrierModule();
    const named = [...mod.namedParameters("root")];
    const names = named.map(([name]) => name);
    expect(names).toContain("root.p");
  });

  it("namedParameters(recurse=false) yields only own params", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const named = [...root.namedParameters("", false)];
    expect(named.length).toBe(1);
    expect(named[0][0]).toBe("p");
  });

  it("buffers() yields own and child buffers recursively", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const bufs = [...root.buffers(true)];
    expect(bufs.length).toBe(2);
  });

  it("buffers(recurse=false) yields only own buffers", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const bufs = [...root.buffers(false)];
    expect(bufs.length).toBe(1);
  });

  it("namedBuffers() yields prefixed names recursively", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const named = [...root.namedBuffers()];
    const names = named.map(([name]) => name);
    expect(names).toContain("b");
    expect(names).toContain("child.b");
  });

  it("namedBuffers(prefix) prepends the prefix", () => {
    const mod = new ParamCarrierModule();
    const named = [...mod.namedBuffers("root")];
    const names = named.map(([name]) => name);
    expect(names).toContain("root.b");
  });

  it("namedBuffers(recurse=false) yields only own buffers", () => {
    const root = new ParamCarrierModule().attach("child", new ParamCarrierModule());
    const named = [...root.namedBuffers("", false)];
    expect(named.length).toBe(1);
    expect(named[0][0]).toBe("b");
  });

  it("modules(recurse=true) yields self and descendants", () => {
    const child = new ParamCarrierModule();
    const root = new ParamCarrierModule().attach("child", child);
    const mods = [...root.modules(true)];
    expect(mods).toContain(root);
    expect(mods).toContain(child);
  });

  it("modules(recurse=false) yields self and direct children only", () => {
    const grandchild = new AddScalarModule(1);
    const child = new ParamCarrierModule().attach("gc", grandchild);
    const root = new ParamCarrierModule().attach("child", child);
    const mods = [...root.modules(false)];
    expect(mods).toContain(root);
    expect(mods).toContain(child);
    expect(mods).not.toContain(grandchild);
  });

  it("namedModules(recurse=true) yields named self and descendants", () => {
    const child = new ParamCarrierModule();
    const root = new ParamCarrierModule().attach("child", child);
    const named = [...root.namedModules()];
    const names = named.map(([name]) => name);
    expect(names).toContain("");
    expect(names).toContain("child");
  });

  it("namedModules(recurse=false) yields named self and direct children only", () => {
    const grandchild = new AddScalarModule(1);
    const child = new ParamCarrierModule().attach("gc", grandchild);
    const root = new ParamCarrierModule().attach("child", child);
    const named = [...root.namedModules("", false)];
    const names = named.map(([name]) => name);
    expect(names).toContain("");
    expect(names).toContain("child");
    expect(names).not.toContain("child.gc");
  });

  it("namedModules with prefix prepends it", () => {
    const root = new ParamCarrierModule().attach("child", new AddScalarModule(1));
    const named = [...root.namedModules("model")];
    const names = named.map(([n]) => n);
    expect(names).toContain("model");
    expect(names).toContain("model.child");
  });

  it("children() yields direct child modules", () => {
    const child1 = new AddScalarModule(1);
    const child2 = new AddScalarModule(2);
    const root = new ParamCarrierModule()
      .attach("a", child1)
      .attach("b", child2);
    const kids = [...root.children()];
    expect(kids).toContain(child1);
    expect(kids).toContain(child2);
    expect(kids.length).toBe(2);
  });

  // ====== Parameter class ======

  it("Parameter exposes shape, dtype, name, grad, requiresGrad", () => {
    const param = new Parameter(new Tensor([1, 2, 3]));
    expect(param.shape).toEqual([3]);
    expect(param.dtype).toBe(DType.FLOAT32);
    expect(param.requiresGrad).toBe(true);
    expect(param.grad).toBe(null);
    param.name = "test_param";
    expect(param.name).toBe("test_param");
  });

  it("Parameter.data setter updates the underlying tensor", async () => {
    const param = new Parameter(new Tensor([1, 2]));
    param.data = new Tensor([5, 6]);
    expect(await param.data.toArray()).toEqual([5, 6]);
  });

  it("Parameter.zeroGrad clears gradient", () => {
    const param = new Parameter(new Tensor([1]), true);
    param.zeroGrad();
    expect(param.grad).toBe(null);
  });

  it("Parameter.detach returns a tensor without grad", () => {
    const param = new Parameter(new Tensor([1, 2]));
    const detached = param.detach();
    expect(detached).toBeInstanceOf(Tensor);
    expect(detached.requiresGrad).toBe(false);
  });

  it("Parameter.clone returns a new Parameter with same data", async () => {
    const param = new Parameter(new Tensor([3, 4]), true);
    const cloned = param.clone();
    expect(cloned).toBeInstanceOf(Parameter);
    expect(await cloned.data.toArray()).toEqual([3, 4]);
    expect(cloned.requiresGrad).toBe(true);
  });

  it("Parameter constructed from number[] sets requiresGrad", () => {
    const param = new Parameter([1, 2, 3], false);
    expect(param.requiresGrad).toBe(false);
    expect(param.shape).toEqual([3]);
  });

  it("Parameter.toDevice transfers tensor to given device", async () => {
    const param = new Parameter(new Tensor([1, 2]));
    await param.toDevice(Device.cpu());
    expect(await param.data.toArray()).toEqual([1, 2]);
  });

  // ====== Buffer class ======

  it("Buffer exposes name, data, persistent", () => {
    const buf = new Buffer(new Tensor([10, 20]));
    expect(buf.persistent).toBe(true);
    buf.name = "test_buf";
    expect(buf.name).toBe("test_buf");
  });

  it("Buffer.data setter updates the underlying tensor", async () => {
    const buf = new Buffer(new Tensor([10]));
    buf.data = new Tensor([99]);
    expect(await buf.data.toArray()).toEqual([99]);
  });

  it("Buffer with persistent=false", () => {
    const buf = new Buffer(new Tensor([1]), false);
    expect(buf.persistent).toBe(false);
  });

  it("Buffer constructed from number[] creates tensor", async () => {
    const buf = new Buffer([5, 6, 7]);
    expect(await buf.data.toArray()).toEqual([5, 6, 7]);
  });

  it("Buffer.toDevice transfers tensor", async () => {
    const buf = new Buffer(new Tensor([1, 2]));
    await buf.toDevice(Device.cpu());
    expect(await buf.data.toArray()).toEqual([1, 2]);
  });

  // ====== Module Gradient Management ======

  it("zeroGrad() clears gradients on all parameters", () => {
    const mod = new ParamCarrierModule();
    mod.zeroGrad();
    for (const p of mod.parameters()) {
      expect(p.grad).toBe(null);
    }
  });

  it("requiresGrad_() sets requiresGrad on all parameters", () => {
    const mod = new ParamCarrierModule();
    mod.requiresGrad_(false);
    for (const p of mod.parameters()) {
      expect(p.data.requiresGrad).toBe(false);
    }
    mod.requiresGrad_(true);
    for (const p of mod.parameters()) {
      expect(p.data.requiresGrad).toBe(true);
    }
  });

  // ====== numParameters ======

  it("numParameters() counts all parameter elements", () => {
    const mod = new ParamCarrierModule(); // p has [1,2] so 2 elements
    expect(mod.numParameters()).toBe(2);
  });

  it("numParameters(onlyTrainable=true) counts only trainable params", () => {
    // ParamCarrierModule's p has requiresGrad=true by default
    const mod = new ParamCarrierModule();
    // param.requiresGrad checks the Parameter's _requiresGrad field
    expect(mod.numParameters(true)).toBe(2);
    // numParameters(false) counts all params regardless
    expect(mod.numParameters(false)).toBe(2);
  });

  // ====== apply ======

  it("apply() calls function on every module including self", () => {
    const root = new ParamCarrierModule().attach("child", new AddScalarModule(1));
    const visited: Module[] = [];
    root.apply((m) => visited.push(m));
    expect(visited.length).toBe(2);
    expect(visited).toContain(root);
  });

  // ====== Module name ======

  it("Module.name falls back to constructor name if not set", () => {
    const mod = new AddScalarModule(1);
    expect(mod.name).toBe("AddScalarModule");
    mod.name = "custom_name";
    expect(mod.name).toBe("custom_name");
  });

  // ====== toString / extraRepr ======

  it("Module.toString() includes constructor name and child modules", () => {
    const root = new ParamCarrierModule().attach("child", new AddScalarModule(1));
    const str = root.toString();
    expect(str).toContain("ParamCarrierModule");
    expect(str).toContain("(child): AddScalarModule");
  });

  it("Module.toString() includes extraRepr output", () => {
    const mod = new ExtraReprModule(10, 20);
    const str = mod.toString();
    expect(str).toContain("in_features=10");
    expect(str).toContain("out_features=20");
  });

  it("Module.toString() handles multi-level nesting", () => {
    const gc = new AddScalarModule(1);
    const child = new ParamCarrierModule().attach("gc", gc);
    const root = new ParamCarrierModule().attach("child", child);
    const str = root.toString();
    expect(str).toContain("ParamCarrierModule");
    expect(str).toContain("(child): ParamCarrierModule");
    expect(str).toContain("(gc): AddScalarModule");
  });

  // ====== Device Transfer (Module.to / cpu / gpu) ======

  it("Module.to(device) transfers params and buffers", async () => {
    const mod = new ParamCarrierModule();
    const result = await mod.to(Device.cpu());
    expect(result).toBe(mod);
    expect(await mod.p.data.toArray()).toEqual([1, 2]);
  });

  it("Module.cpu() transfers to cpu device", async () => {
    const mod = new ParamCarrierModule();
    const result = await mod.cpu();
    expect(result).toBe(mod);
  });

  it("Module.gpu() throws when no GPU device is available", async () => {
    const mod = new ParamCarrierModule();
    await expect(mod.gpu()).rejects.toThrow(/no gpu device/i);
  });

  // ====== ModuleDict ======

  it("ModuleDict/ParameterList/ParameterDict basic mutations work", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const dict = new ModuleDict({ one: m1 });
    dict.set("two", m2);
    expect(dict.size).toBe(2);
    expect(dict.get("two")).toBe(m2);
    expect(dict.delete("one")).toBe(true);
    expect(dict.has("one")).toBe(false);

    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const pList = new ParameterList([p1]);
    pList.append(p2);
    expect(pList.length).toBe(2);
    expect(pList.get(-1)).toBe(p2);

    const pDict = new ParameterDict({ a: p1 });
    pDict.set("b", p2);
    expect(pDict.size).toBe(2);
    pDict.clear();
    expect(pDict.size).toBe(0);
  });

  it("ModuleDict constructed from array of pairs", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const dict = new ModuleDict([
      ["a", m1],
      ["b", m2],
    ]);
    expect(dict.size).toBe(2);
    expect(dict.get("a")).toBe(m1);
    expect(dict.get("b")).toBe(m2);
  });

  it("ModuleDict.forward() throws", () => {
    const dict = new ModuleDict();
    expect(() => dict.forward(new Tensor([1]))).toThrow(
      /does not implement forward/i
    );
  });

  it("ModuleDict.keys/values/entries return iterators", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const dict = new ModuleDict({ a: m1, b: m2 });
    expect([...dict.keys()]).toEqual(["a", "b"]);
    expect([...dict.values()]).toEqual([m1, m2]);
    expect([...dict.entries()]).toEqual([
      ["a", m1],
      ["b", m2],
    ]);
  });

  it("ModuleDict is iterable", () => {
    const m1 = new AddScalarModule(1);
    const dict = new ModuleDict({ x: m1 });
    const collected = [...dict];
    expect(collected).toEqual([["x", m1]]);
  });

  it("ModuleDict.clear removes all modules", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const dict = new ModuleDict({ a: m1, b: m2 });
    dict.clear();
    expect(dict.size).toBe(0);
    expect(dict.has("a")).toBe(false);
  });

  it("ModuleDict.update from record", () => {
    const m1 = new AddScalarModule(1);
    const m2 = new AddScalarModule(2);
    const dict = new ModuleDict();
    dict.update({ a: m1, b: m2 });
    expect(dict.size).toBe(2);
  });

  it("ModuleDict.update from array of pairs", () => {
    const m1 = new AddScalarModule(1);
    const dict = new ModuleDict();
    dict.update([["x", m1]]);
    expect(dict.get("x")).toBe(m1);
  });

  it("ModuleDict.pop removes and returns the module, or undefined", () => {
    const m1 = new AddScalarModule(1);
    const dict = new ModuleDict({ a: m1 });
    const popped = dict.pop("a");
    expect(popped).toBe(m1);
    expect(dict.size).toBe(0);
    expect(dict.pop("nonexistent")).toBeUndefined();
  });

  it("ModuleDict.delete returns false for non-existent key", () => {
    const dict = new ModuleDict();
    expect(dict.delete("nonexistent")).toBe(false);
  });

  it("ModuleDict.get returns undefined for non-existent key", () => {
    const dict = new ModuleDict();
    expect(dict.get("missing")).toBeUndefined();
  });

  it("ModuleDict constructed without arguments", () => {
    const dict = new ModuleDict();
    expect(dict.size).toBe(0);
  });

  // ====== ParameterList ======

  it("ParameterList.forward() throws", () => {
    const pList = new ParameterList();
    expect(() => pList.forward(new Tensor([1]))).toThrow(
      /does not implement forward/i
    );
  });

  it("ParameterList.extend adds multiple parameters", () => {
    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const pList = new ParameterList();
    pList.extend([p1, p2]);
    expect(pList.length).toBe(2);
  });

  it("ParameterList.set replaces parameter at index (including negative)", () => {
    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const replacement = new Parameter(new Tensor([99]));
    const pList = new ParameterList([p1, p2]);
    pList.set(-1, replacement);
    expect(pList.get(1)).toBe(replacement);
  });

  it("ParameterList is iterable", () => {
    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const pList = new ParameterList([p1, p2]);
    const collected = [...pList];
    expect(collected).toEqual([p1, p2]);
  });

  it("ParameterList constructed without arguments has zero length", () => {
    const pList = new ParameterList();
    expect(pList.length).toBe(0);
  });

  // ====== ParameterDict ======

  it("ParameterDict.forward() throws", () => {
    const pDict = new ParameterDict();
    expect(() => pDict.forward(new Tensor([1]))).toThrow(
      /does not implement forward/i
    );
  });

  it("ParameterDict constructed from array of pairs", () => {
    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const pDict = new ParameterDict([
      ["a", p1],
      ["b", p2],
    ]);
    expect(pDict.size).toBe(2);
    expect(pDict.get("a")).toBe(p1);
  });

  it("ParameterDict.keys/values/entries return iterators", () => {
    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const pDict = new ParameterDict({ x: p1, y: p2 });
    expect([...pDict.keys()]).toEqual(["x", "y"]);
    expect([...pDict.values()]).toEqual([p1, p2]);
    expect([...pDict.entries()]).toEqual([
      ["x", p1],
      ["y", p2],
    ]);
  });

  it("ParameterDict is iterable", () => {
    const p1 = new Parameter(new Tensor([1]));
    const pDict = new ParameterDict({ x: p1 });
    const collected = [...pDict];
    expect(collected).toEqual([["x", p1]]);
  });

  it("ParameterDict.delete removes param and returns true, or false if missing", () => {
    const p1 = new Parameter(new Tensor([1]));
    const pDict = new ParameterDict({ a: p1 });
    expect(pDict.delete("a")).toBe(true);
    expect(pDict.size).toBe(0);
    expect(pDict.delete("nonexistent")).toBe(false);
  });

  it("ParameterDict.has checks existence", () => {
    const p1 = new Parameter(new Tensor([1]));
    const pDict = new ParameterDict({ a: p1 });
    expect(pDict.has("a")).toBe(true);
    expect(pDict.has("b")).toBe(false);
  });

  it("ParameterDict.update from record", () => {
    const p1 = new Parameter(new Tensor([1]));
    const p2 = new Parameter(new Tensor([2]));
    const pDict = new ParameterDict();
    pDict.update({ a: p1, b: p2 });
    expect(pDict.size).toBe(2);
  });

  it("ParameterDict.update from array of pairs", () => {
    const p1 = new Parameter(new Tensor([1]));
    const pDict = new ParameterDict();
    pDict.update([["x", p1]]);
    expect(pDict.get("x")).toBe(p1);
  });

  it("ParameterDict constructed without arguments", () => {
    const pDict = new ParameterDict();
    expect(pDict.size).toBe(0);
  });

  it("ParameterDict.get returns undefined for missing key", () => {
    const pDict = new ParameterDict();
    expect(pDict.get("missing")).toBeUndefined();
  });
});
