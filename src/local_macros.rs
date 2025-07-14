#[rustfmt::skip]
macro_rules! repeat64 {
    ($i:ident, $b:block) => {
        let $i = 0; $b; let $i = 1; $b; let $i = 2; $b; let $i = 3; $b;
        let $i = 4; $b; let $i = 5; $b; let $i = 6; $b; let $i = 7; $b;
        let $i = 8; $b; let $i = 9; $b; let $i = 10; $b; let $i = 11; $b;
        let $i = 12; $b; let $i = 13; $b; let $i = 14; $b; let $i = 15; $b;
        let $i = 16; $b; let $i = 17; $b; let $i = 18; $b; let $i = 19; $b;
        let $i = 20; $b; let $i = 21; $b; let $i = 22; $b; let $i = 23; $b;
        let $i = 24; $b; let $i = 25; $b; let $i = 26; $b; let $i = 27; $b;
        let $i = 28; $b; let $i = 29; $b; let $i = 30; $b; let $i = 31; $b;
        let $i = 32; $b; let $i = 33; $b; let $i = 34; $b; let $i = 35; $b;
        let $i = 36; $b; let $i = 37; $b; let $i = 38; $b; let $i = 39; $b;
        let $i = 40; $b; let $i = 41; $b; let $i = 42; $b; let $i = 43; $b;
        let $i = 44; $b; let $i = 45; $b; let $i = 46; $b; let $i = 47; $b;
        let $i = 48; $b; let $i = 49; $b; let $i = 50; $b; let $i = 51; $b;
        let $i = 52; $b; let $i = 53; $b; let $i = 54; $b; let $i = 55; $b;
        let $i = 56; $b; let $i = 57; $b; let $i = 58; $b; let $i = 59; $b;
        let $i = 60; $b; let $i = 61; $b; let $i = 62; $b; let $i = 63; $b;
    };
}
