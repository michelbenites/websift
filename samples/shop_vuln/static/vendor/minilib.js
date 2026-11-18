// Tiny vendored DOM helper, bundled with the sample shop.

var minilib = {
    setHtml: function (elementId, html) {
        var el = document.getElementById(elementId);
        el.innerHTML = html;
    },

    appendHtml: function (elementId, html) {
        var el = document.getElementById(elementId);
        el.innerHTML = el.innerHTML + html;
    },

    byId: function (elementId) {
        return document.getElementById(elementId);
    }
};
