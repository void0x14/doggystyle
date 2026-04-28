const std = @import("std");
const audio_bypass = @import("arkose/audio_bypass.zig");
const audio_injector = @import("arkose/audio_injector.zig");

fn runtimeStringValue(comptime value: []const u8) []const u8 {
    return "{\"result\":{\"result\":{\"type\":\"string\",\"value\":\"" ++ value ++ "\"}}}";
}

fn runtimeStringValueJson(comptime value: []const u8) []const u8 {
    return "{\"result\":{\"result\":{\"type\":\"string\",\"value\":\"" ++ value ++ "\"}}}";
}

test "audio_injector: submit response classification uses only Runtime.evaluate string value" {
    const cases = [_]struct {
        name: []const u8,
        response: []const u8,
        expected: bool,
    }{
        .{ .name = "clicked_text_submit", .response = runtimeStringValue("clicked_text_submit"), .expected = false },
        .{ .name = "clicked_input_submit", .response = runtimeStringValue("clicked_input_submit"), .expected = false },
        .{ .name = "clicked_fallback_button", .response = runtimeStringValue("clicked_fallback_button"), .expected = false },
        .{ .name = "submitted", .response = runtimeStringValue("submitted"), .expected = false },
        .{ .name = "success", .response = runtimeStringValue("success"), .expected = false },
        .{ .name = "no_submit", .response = runtimeStringValue("no_submit"), .expected = false },
        .{ .name = "not_clicked", .response = runtimeStringValue("not_clicked"), .expected = false },
        .{ .name = "not_submitted", .response = runtimeStringValue("not_submitted"), .expected = false },
        .{ .name = "unsuccessful", .response = runtimeStringValue("unsuccessful"), .expected = false },
        .{ .name = "json_success_false", .response = "{\"result\":{\"result\":{\"type\":\"object\",\"value\":{\"success\":false}}}}", .expected = false },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected, audio_injector.submitResponseSucceeded(case.response));
    }
}

test "audio_injector: clicked_text_submit alone is not accepted proof" {
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, runtimeStringValue("clicked_text_submit"));

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.clicked, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: wrong post-submit text produces wrong verdict" {
    const response = runtimeStringValueJson("{\\\"submit_result\\\":\\\"clicked_text_submit\\\",\\\"input_value\\\":\\\"2\\\",\\\"body_text_snippet\\\":\\\"Incorrect. Only enter the number of your chosen answer, e.g. 1\\\",\\\"wrong_text\\\":true,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.wrong, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: completion post-submit text produces complete verdict" {
    const response = runtimeStringValueJson("{\\\"submit_result\\\":\\\"clicked_text_submit\\\",\\\"input_value\\\":\\\"3\\\",\\\"body_text_snippet\\\":\\\"Verification complete. You are all set.\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":true}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.complete, proof.verdict);
    try std.testing.expect(proof.accepted());
}

test "audio_injector: neutral structured post-submit proof is unknown" {
    const response = runtimeStringValueJson("{\\\"submit_result\\\":\\\"submitted\\\",\\\"input_value\\\":\\\"2\\\",\\\"body_text_snippet\\\":\\\"Choose the matching audio.\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    // input_visible is missing → no input_visible field means we don't have DOM visibility data
    // Missing field defaults to null, so classifyPostSubmitProof() won't enter the transition branch
    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: input disappeared without wrong/complete text is transition" {
    // SOURCE: Arkose DOM — after correct answer, input element offsetParent becomes null
    // Body text has no "incorrect" or "verification complete" — intermediate challenge loading
    const response = runtimeStringValueJson("{\\\"submit_result\\\":\\\"clicked_text_submit\\\",\\\"input_value\\\":\\\"\\\",\\\"input_visible\\\":false,\\\"body_text_snippet\\\":\\\"Select the matching audio.\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.transition, proof.verdict);
    try std.testing.expect(proof.accepted());
}

test "audio_injector: input still visible without wrong/complete text is unknown" {
    // SOURCE: Arkose is still processing — input visible, no verdict text yet
    const response = runtimeStringValueJson("{\\\"submit_result\\\":\\\"clicked_text_submit\\\",\\\"input_value\\\":\\\"2\\\",\\\"input_visible\\\":true,\\\"body_text_snippet\\\":\\\"Loading...\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: malformed post-submit proof is unknown" {
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, runtimeStringValueJson("{bad-json"));

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: direct submitted string is unknown not complete" {
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, runtimeStringValue("submitted"));

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: direct success string is unknown not complete" {
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, runtimeStringValue("success"));

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_bypass: challenge loop continues until completion signal or safety limit" {
    try std.testing.expect(audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 1,
        .attempted = 1,
        .target_challenges = 2,
        .challenge_complete = false,
    }));
    try std.testing.expect(!audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 2,
        .attempted = 2,
        .target_challenges = 2,
        .challenge_complete = true,
    }));
    try std.testing.expect(audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 2,
        .attempted = 2,
        .target_challenges = 2,
        .challenge_complete = false,
    }));
    try std.testing.expect(!audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 1,
        .attempted = audio_bypass.MAX_CHALLENGES,
        .target_challenges = 2,
        .challenge_complete = false,
    }));
    try std.testing.expect(!audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 0,
        .attempted = audio_bypass.MAX_CHALLENGES,
        .target_challenges = audio_bypass.MAX_CHALLENGES,
        .challenge_complete = false,
    }));
}

test "audio_bypass: challenge loop uses target only for progress, completion still required" {
    try std.testing.expect(audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 2,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = false,
    }));

    try std.testing.expect(audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 3,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = false,
    }));
}

test "audio_bypass: final success requires completion after target submissions reached" {
    try std.testing.expect(!audio_bypass.audioBypassFinalSuccess(.{
        .successful_submits = 3,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = false,
    }));

    try std.testing.expect(audio_bypass.audioBypassFinalSuccess(.{
        .successful_submits = 3,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = true,
    }));
}

test "audio_bypass: final success is false when target is zero without completion" {
    try std.testing.expect(!audio_bypass.audioBypassFinalSuccess(.{
        .successful_submits = 0,
        .attempted = 0,
        .target_challenges = 0,
        .challenge_complete = false,
    }));
}

test "audio_bypass: gfct Runtime.evaluate string value with three audio urls returns target three" {
    const allocator = std.testing.allocator;
    const gfct_three =
        "{\"id\":21,\"result\":{\"result\":{\"type\":\"string\",\"value\":\"{\\\"challengeID\\\":\\\"abcdef\\\",\\\"audio_challenge_urls\\\":[\\\"https://a.test/1.mp3\\\",\\\"https://a.test/2.mp3\\\",\\\"https://a.test/3.mp3\\\"]}\"}}}";

    try std.testing.expectEqual(@as(u8, 3), try audio_bypass.parseAudioChallengeTargetFromGfctResponse(allocator, gfct_three));
}

test "audio_bypass: gfct Runtime.evaluate audio_challenge_urls count defines target" {
    const allocator = std.testing.allocator;
    const gfct_two =
        "{\"id\":17,\"result\":{\"result\":{\"type\":\"string\",\"value\":\"{\\\"challengeID\\\":\\\"abcdef\\\",\\\"audio_challenge_urls\\\":[\\\"https://a.test/1.mp3\\\",\\\"https://a.test/2.mp3\\\"]}\"}}}";
    const gfct_three =
        "{\"id\":18,\"result\":{\"result\":{\"type\":\"string\",\"value\":\"{\\\"challengeID\\\":\\\"abcdef\\\",\\\"audio_challenge_urls\\\":[\\\"https://a.test/1.mp3\\\",\\\"https://a.test/2.mp3\\\",\\\"https://a.test/3.mp3\\\"]}\"}}}";

    try std.testing.expectEqual(@as(u8, 2), try audio_bypass.parseAudioChallengeTargetFromGfctResponse(allocator, gfct_two));
    try std.testing.expectEqual(@as(u8, 3), try audio_bypass.parseAudioChallengeTargetFromGfctResponse(allocator, gfct_three));
}

test "audio_injector: intermediate transition when input gone but no wrong/complete text" {
    // Simulates: correct answer on challenge 0 of 3, Arkose loads challenge 1
    // Body has neutral text (no "Incorrect", no "Verification complete"), input disappeared
    const response = runtimeStringValueJson("{\\\"input_value\\\":\\\"2\\\",\\\"input_visible\\\":false,\\\"body_text_snippet\\\":\\\"Choose the matching audio.\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.transition, proof.verdict);
    try std.testing.expect(proof.accepted());
}

test "audio_injector: transition proof is accepted" {
    const proof = audio_injector.PostSubmitProof{ .verdict = .transition };
    try std.testing.expect(proof.accepted());
}

test "audio_injector: input still visible after submit is unknown not transition" {
    // Simulates: submit clicked but Arkose hasn't processed yet
    // Input still visible, body neutral → should be unknown (waiting)
    const response = runtimeStringValueJson("{\\\"input_value\\\":\\\"2\\\",\\\"input_visible\\\":true,\\\"body_text_snippet\\\":\\\"Choose the matching audio.\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: no input_visible field falls through to unknown" {
    // Backward compat: old payload format without input_visible field
    const response = runtimeStringValueJson("{\"input_value\":\\\"2\\\",\\\"body_text_snippet\\\":\\\"Choose audio.\\\",\\\"wrong_text\\\":false,\\\"completion_text\\\":false}");
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, response);

    // input_visible=null → can't determine if transition → stays unknown
    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}

test "audio_injector: broken JSON with complet text still unknown" {
    // Malformed JSON → extract fails → unknown (not transition, not complete)
    const proof = audio_injector.classifyPostSubmitProof(std.testing.allocator, runtimeStringValueJson("{bad-json-with-complet"));

    try std.testing.expectEqual(audio_injector.PostSubmitVerdict.unknown, proof.verdict);
    try std.testing.expect(!proof.accepted());
}
