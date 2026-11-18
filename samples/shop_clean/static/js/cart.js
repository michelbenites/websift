// Cart page behavior for the clean sample shop.

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

function showPromoBanner(promoText) {
    var banner = document.getElementById("promo-banner");
    banner.textContent = promoText;
}

function showProductBlurb(blurb) {
    var target = document.getElementById("product-blurb");
    target.textContent = blurb;
}

function logShippingNotice(notice) {
    var el = document.createElement("p");
    el.textContent = notice;
    document.getElementById("shipping-log").appendChild(el);
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
