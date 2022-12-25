/* Constant Value */
const DOI_TYPE = {
    MOST_CARE: 1 << 0,
    MEDIEAN_CARE: 1 << 1,
    LITTLE_CARE: 1 << 2,
    DONT_CARE: 1 << 3
}

const TEXT_PADDING = {
    HEAD_TOP: 1,
    HEAD_BOTTOM: 5,
    HEAD_HEIGHT: 12,
    CONTENT_TOP: 5,
    CONTENT_BOTTOM: 5,
    CONTENT_LEFT: 10,
    CONTENT_HEIGHT: 12,
    TEXT_WIDTH: 6.5
}

const NODE_COLOR = {
    NORMAL: "#fff",
    MOST_FOCUS: `hsl(200, 83%, 83%)`, //"#FFB14E",
    MEDIEAN_FOCUS: `hsl(200, 95%, 95%)`, // "#FFD700",
    FOLD: `hsl(100, 100%, 90%)`,
    MERGE: `hsl(130, 90%, 90%)`,
    FOLD_AND_MERGE: `hsl(360, 100%, 90%)`
}

const TEXTAREA = {
    HEIGHT_PADDING: 6.02,
    LINE_HEIGHT: 15.33
};

const width = 2048;     // outer width, in pixels
const height = 4096;    // outer height, in pixels
const margin = 100;     // shorthand for margins
const duration = 350;   // animation duration
const roundScale = 5;   // node rect round scale