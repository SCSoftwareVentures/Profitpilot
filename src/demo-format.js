// Presentation-only formatter for synthetic dashboard amounts. No Number conversion.
export function formatDemoMoney(value){
  if(typeof value!=="string"||! /^-?(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(value))return "Unavailable";
  const negative=value.startsWith("-");
  const unsigned=negative?value.slice(1):value;
  const [whole,fraction=""]=unsigned.split(".");
  const grouped=whole.replace(/\B(?=(\d{3})+(?!\d))/g,",");
  return (negative?"−":"")+"$"+grouped+"."+fraction.padEnd(2,"0");
}
