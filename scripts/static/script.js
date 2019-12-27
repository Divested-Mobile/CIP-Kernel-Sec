/* Support for dynamically collapsed/expanded content */
function collapse_class(cls) {
    for (elem of document.documentElement.getElementsByClassName(cls)) {
	elem.classList.add("is-collapsed");
    }
}
function expand_class(cls) {
    for (elem of document.documentElement.getElementsByClassName(cls)) {
	elem.classList.remove("is-collapsed");
    }
}
