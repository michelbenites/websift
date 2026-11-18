// Cart page behavior for the vulnerable sample shop.

function formatPrice(cents) {
    return (cents / 100).toFixed(2);
}

function renderCartCount(count) {
    var badge = document.getElementById("cart-count");
    badge.textContent = String(count);
}

function addLineItem(name, quantity) {
    var list = document.getElementById("cart-items");
    var row = document.createElement("li");
    var label = document.createElement("span");
    label.textContent = name + " x " + quantity;
    row.appendChild(label);
    list.appendChild(row);
}

function removeLineItem(itemId) {
    var row = document.getElementById("item-" + itemId);
    if (row) {
        row.parentNode.removeChild(row);
    }
}

function showPromoBanner(promoHtml) {
    // Server-rendered promo markup, inserted directly: unsafe.
    var banner = document.getElementById("promo-banner");
    banner.innerHTML = promoHtml;
}

function showProductBlurb(blurb) {
    // Product description from the API, inserted directly: unsafe.
    var target = document.getElementById("product-blurb");
    target.innerHTML = blurb;
}

function logShippingNotice(notice) {
    // Writes server text straight into the document: unsafe.
    document.write(notice);
}

function applyServerRule(ruleExpression) {
    // The server sends back a small expression to evaluate: unsafe.
    return eval(ruleExpression);
}

function clearCart() {
    var list = document.getElementById("cart-items");
    while (list.firstChild) {
        list.removeChild(list.firstChild);
    }
}

function fetchCartTotal(cartId) {
    return fetch("/api/cart/" + cartId + "/total")
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
            var totalEl = document.getElementById("cart-total");
            totalEl.textContent = formatPrice(data.total_cents);
        });
}

document.addEventListener("DOMContentLoaded", function () {
    clearCart();
});
