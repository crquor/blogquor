$(document).ready(function () {
    $("#searchInput").on("input", function () {
        let query = $(this).val().trim();

        if (query) {
            $.ajax({
                url: "/searchResults",
                method: "POST",
                contentType: "application/json",
                data: JSON.stringify({ q: query }),
                success: function (data) {
                    let resultsList = $("#searchPost-column");
                    resultsList.empty(); // Clear previous results

                    if (data.length > 0) {
                        data.forEach(function (item) {
                            resultsList.append(`<div class="search-post">
      <a href="/${item.author_username}/posts/${item.id}" class="search-post-title-link" target="_top">
        <h2>${item.title}</h2>
      </a>
      <br>
      <strong>Published on: ${item.created_at}</strong>
      <br>
      <br>
      <p>${item.post_description}</p>
      <br>
    </div>`);
                        });
                    } else {
                        resultsList.append('<div class="search-post"><h3>No posts found</h3></div>');
                    }
                },
                error: function () {
                    alert("Error while fetching data!");
                },
            });
        } else {
            $("#results").empty(); // Clear results if input is empty
        }
    });
});