//! Table component

use leptos::prelude::*;

/// Table column definition
#[derive(Clone)]
pub struct TableColumn<T: Clone + 'static> {
    pub key: String,
    pub label: String,
    pub render: Box<dyn Fn(&T) -> View + Send + Sync>,
    pub sortable: bool,
}

impl<T: Clone + 'static> TableColumn<T> {
    pub fn new(
        key: impl Into<String>,
        label: impl Into<String>,
        render: impl Fn(&T) -> View + Send + Sync + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            render: Box::new(render),
            sortable: false,
        }
    }

    pub fn sortable(mut self) -> Self {
        self.sortable = true;
        self
    }
}

/// Generic table component
#[component]
pub fn Table<T: Clone + 'static>(
    #[prop(into)] columns: Vec<TableColumn<T>>,
    #[prop(into)] data: Signal<Vec<T>>,
    #[prop(into, optional)] loading: Signal<bool>,
    #[prop(into, optional)] empty_message: String,
    #[prop(into, optional)] class: String,
) -> impl IntoView {
    let empty_message = if empty_message.is_empty() {
        "No data available".to_string()
    } else {
        empty_message
    };

    view! {
        <div class=format!("table-container {}", class)>
            <table class="table">
                <thead>
                    <tr>
                        {columns.iter().map(|col| {
                            view! {
                                <th class=if col.sortable { "sortable" } else { "" }>
                                    {col.label.clone()}
                                </th>
                            }
                        }).collect_view()}
                    </tr>
                </thead>
                <tbody>
                    {move || {
                        if loading.get() {
                            view! {
                                <tr>
                                    <td colspan=columns.len().to_string() class="table-loading">
                                        <span class="loading-spinner"></span>
                                        "Loading..."
                                    </td>
                                </tr>
                            }.into_any()
                        } else if data.get().is_empty() {
                            view! {
                                <tr>
                                    <td colspan=columns.len().to_string() class="table-empty">
                                        {empty_message.clone()}
                                    </td>
                                </tr>
                            }.into_any()
                        } else {
                            data.get().into_iter().map(|row| {
                                let row_clone = row.clone();
                                view! {
                                    <tr>
                                        {columns.iter().map(|col| {
                                            view! {
                                                <td>{(col.render)(&row_clone)}</td>
                                            }
                                        }).collect_view()}
                                    </tr>
                                }
                            }).collect_view().into_any()
                        }
                    }}
                </tbody>
            </table>
        </div>
    }
}

/// Pagination component
#[component]
pub fn Pagination(
    #[prop(into)] current_page: Signal<u32>,
    #[prop(into)] total_pages: Signal<u32>,
    on_page_change: Callback<u32>,
) -> impl IntoView {
    let pages = move || {
        let current = current_page.get();
        let total = total_pages.get();
        let mut pages = Vec::new();

        // Always show first page
        pages.push(1);

        // Show pages around current
        let start = (current.saturating_sub(2)).max(2);
        let end = (current + 2).min(total.saturating_sub(1));

        if start > 2 {
            pages.push(0); // Ellipsis
        }

        for p in start..=end {
            pages.push(p);
        }

        if end < total.saturating_sub(1) {
            pages.push(0); // Ellipsis
        }

        // Always show last page
        if total > 1 {
            pages.push(total);
        }

        pages
    };

    view! {
        <div class="pagination">
            <button
                type="button"
                class="pagination-btn"
                disabled=move || current_page.get() <= 1
                on:click=move |_| {
                    let page = current_page.get();
                    if page > 1 {
                        on_page_change.call(page - 1);
                    }
                }
            >
                "Previous"
            </button>

            <div class="pagination-pages">
                {move || pages().into_iter().map(|p| {
                    if p == 0 {
                        view! { <span class="pagination-ellipsis">"..."</span> }.into_any()
                    } else {
                        let is_current = current_page.get() == p;
                        view! {
                            <button
                                type="button"
                                class=format!("pagination-page {}", if is_current { "active" } else { "" })
                                on:click=move |_| on_page_change.call(p)
                            >
                                {p}
                            </button>
                        }.into_any()
                    }
                }).collect_view()}
            </div>

            <button
                type="button"
                class="pagination-btn"
                disabled=move || current_page.get() >= total_pages.get()
                on:click=move |_| {
                    let page = current_page.get();
                    let total = total_pages.get();
                    if page < total {
                        on_page_change.call(page + 1);
                    }
                }
            >
                "Next"
            </button>
        </div>
    }
}
