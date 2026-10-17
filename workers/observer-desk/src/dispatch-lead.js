function alignDispatchLead(dispatch) {
  if (!dispatch || typeof dispatch !== "object" || !dispatch.lead) return dispatch;
  const first = Array.isArray(dispatch.items) ? dispatch.items.find((item) => item?.headline && item?.summary) : null;
  if (!first) return dispatch;
  const keyMessage = String(dispatch.lead.title || "").trim();
  const lead = { ...dispatch.lead, title: first.headline, summary: first.summary, lead_item_id: first.id || null };
  if (keyMessage && keyMessage !== first.headline) lead.context = keyMessage;
  else delete lead.context;
  return { ...dispatch, lead };
}

export { alignDispatchLead };
