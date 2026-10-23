import { describe, expect, it } from "vitest";
import { mainlandPublicDns, OVERSEAS_SYSTEM_DNS } from "../src/lib/systemDns";

describe("system DNS", () => {
  it("flags known mainland public resolvers and ignores loopback and overseas DNS", () => {
    expect(
      mainlandPublicDns([
        "114.114.114.114",
        "127.0.0.1",
        "1.1.1.1",
        "8.8.8.8",
        "8.8.4.4",
      ]),
    ).toEqual(["114.114.114.114"]);
    expect(mainlandPublicDns(["223.5.5.5", "223.5.5.5"])).toEqual([
      "223.5.5.5",
    ]);
    expect(mainlandPublicDns(["119.29.29.29%en0"])).toEqual(["119.29.29.29"]);
    expect(mainlandPublicDns(["127.0.0.1", "192.168.10.1", "1.1.1.1"])).toEqual(
      [],
    );
    expect(mainlandPublicDns([])).toEqual([]);
    expect(mainlandPublicDns([...OVERSEAS_SYSTEM_DNS])).toEqual([]);
  });
});
