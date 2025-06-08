#! /usr/bin/env Rscript --vanilla

library(tidyverse)
library(patchwork)
library(cowplot)
library(scales)


browser.hps <- 5e6 / mean(c(
        0.105, 1.69, 1.06, 1.89, 1.91, 1.09, 1.80, 0.97, 0.71, 1.15, 3.59, 1.09, 0.14, 3.98, 1.26, 1.05, 1.26
    ))

hps <- tribble(
    ~environment, ~hps,
    "official.browser", browser.hps,
    "simd.avx512.1thread", 5e7 / 0.59855,
    "official.autovectorized.1thread", 5e7 / 2.6573,
    "official.generic.x86.1thread", 5e7 / 4.696,
    "gpu.wgpu (unoptimized)", 5e7 / 0.22723,
) |>
    mutate(
        environment = fct_reorder(environment, hps, .desc = TRUE),
    )

plots <- list()

p <- map2(c(1000000, 5000000, 10000000, 50000000), c("bottom", "none", "bottom", "none"), \(difficulty, legend.position) {
    df <- tibble(iterations = 2^seq(0, 40, by=0.01)) |>
        mutate(p = pgeom(iterations, 1/difficulty))
    
    browser.t50 <- qgeom(0.5, 1/difficulty) / browser.hps
    browser.t99 <- qgeom(0.99, 1/difficulty) / browser.hps

    df |> 
        cross_join(hps) |>
        mutate(time = iterations / hps) |>
        ggplot(aes(x = time, y = p, color = environment)) +
        geom_line() +
        labs(
            title = sprintf("Time to solve for difficulty %d (extrapolated throughput)", difficulty),
            x = "Time to solve",
            y = "P (X <= t)",
            caption = sprintf("50%% browser: %.2f secs, 99%% browser: %.2f secs", browser.t50, browser.t99)
            ) +
        scale_x_continuous(
          limits = c(0, browser.t99),
          labels = label_timespan(unit = "secs"),
          breaks = c(seq(0, browser.t99, by = if (browser.t99 > 5) 10 else 2), browser.t99, browser.t50)) +
        theme_cowplot() +
        theme(legend.position = legend.position)
}) |> reduce(`+`)

ggsave("time.png", p, width = 18, height = 12, bg = "white", dpi = 300)
