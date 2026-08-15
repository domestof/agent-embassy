function addExtraRow(containerId, rowTemplateHtml) {
  var rows = document.getElementById(containerId);
  var row = document.createElement("div");
  row.className = "extra-row";
  row.innerHTML = rowTemplateHtml;
  rows.appendChild(row);
}
