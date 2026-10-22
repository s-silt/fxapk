import { reconcileCapturedWebScript, stableWebScriptKey, } from "../domain/webInventory.js";
import { requiredScriptSource, sourceExcluded, sourceResult, } from "./CdpCaptureValues.js";
export const captureScripts = async (options) => {
    const { context, events, rawResources, resources, frameIds } = options;
    const state = {
        context,
        events,
        frameIds,
        rawResources,
        resources,
    };
    const drafts = [];
    for (const script of events.scripts.values())
        drafts.push(await buildScriptDraft(script, state));
    if (!context.input.include_script_sources)
        events.completeness.exclude("script_sources", "not_approved", events.scripts.size);
    return keyAndBuildInventory(drafts, events.scripts.size);
};
const buildScriptDraft = async (script, state) => {
    let source = state
        .context.input.include_script_sources
        ? await captureScriptSource(script, state)
        : sourceExcluded("source capture was not selected");
    const inventoryScript = {
        frame_id: state.events.frameForScript(script, state.frameIds),
        url: script.url,
        cdp_hash: script.hash,
        length: script.length,
        is_module: script.isModule,
        language: script.language,
        source_map_url: script.sourceMapUrl,
    };
    return {
        item: {
            ...inventoryScript,
            origin: script.origin,
            resource_reconciliation: reconcileCapturedWebScript({ ...inventoryScript, rawUrl: script.rawUrl }, state.rawResources, state.resources),
            source,
        },
        sourceMapRawUrl: script.sourceMapRawUrl,
    };
};
const captureScriptSource = async (script, state) => {
    const { context } = state;
    const content = requiredScriptSource(await context.connection.send("Debugger.getScriptSource", { scriptId: script.scriptId }, context.sessionId, context.signal), context.operation);
    return sourceResult(content);
};
const keyAndBuildInventory = (drafts, scriptCount) => {
    const keyed = drafts.map((draft) => ({
        ...draft,
        base: stableWebScriptKey(draft.item),
    }));
    keyed.sort((left, right) => left.base.localeCompare(right.base) ||
        sourceDigest(left.item.source).localeCompare(sourceDigest(right.item.source)) ||
        (left.item.frame_id ?? "").localeCompare(right.item.frame_id ?? ""));
    const totals = new Map();
    for (const { base } of keyed)
        totals.set(base, (totals.get(base) ?? 0) + 1);
    const seen = new Map();
    const sourceMapRequests = [];
    const items = keyed.map(({ base, item, sourceMapRawUrl }) => {
        const occurrence = (seen.get(base) ?? 0) + 1;
        seen.set(base, occurrence);
        const scriptKey = totals.get(base) === 1 ? base : `${base}_${String(occurrence)}`;
        if (item.source_map_url !== null && sourceMapRawUrl !== null)
            sourceMapRequests.push({
                scriptKey,
                declaredUrl: item.source_map_url,
                fetchUrl: sourceMapRawUrl,
            });
        return { script_key: scriptKey, ...item };
    });
    return {
        inventory: { total: scriptCount, items },
        sourceMapRequests,
    };
};
const sourceDigest = (source) => (source.included ? source.artifact.sha256 : source.reason);
