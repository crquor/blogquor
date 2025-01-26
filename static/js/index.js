function displaySearch() {
    var id = document.getElementById("searchBox").style.display = "block";

    if (id.style.display === "none") {
        id.style.display = "block";
    }
    else {
        id.style.display == "none"
    }
}

function closeSearch() {
    document.getElementById("searchBox").style.display = "none";
}


function displayAccountModal() {
    var id = document.getElementById("accountModal");

    if (id.style.display === "none") {
        id.style.display = "flex";
    }
    else {
        id.style.display == "none"
    }
}

function closeAccountModal() {
    document.getElementById("accountModal").style.display = "none";
}

function displayBlogSearch() {
    var id = document.getElementById("blogSearchBox").style.display = "block";

    if (id.style.display === "none") {
        id.style.display = "block";
    }
    else {
        id.style.display == "none"
    }
}

function closeBlogSearch() {
    document.getElementById("blogSearchBox").style.display = "none";
}