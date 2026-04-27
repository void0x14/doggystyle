const std = @import("std");
const audio_bypass = @import("arkose/audio_bypass.zig");
const audio_injector = @import("arkose/audio_injector.zig");

fn runtimeStringValue(comptime value: []const u8) []const u8 {
    return "{\"result\":{\"result\":{\"type\":\"string\",\"value\":\"" ++ value ++ "\"}}}";
}

test "audio_injector: submit response classification uses only Runtime.evaluate string value" {
    const cases = [_]struct {
        name: []const u8,
        response: []const u8,
        expected: bool,
    }{
        .{ .name = "clicked_text_submit", .response = runtimeStringValue("clicked_text_submit"), .expected = true },
        .{ .name = "clicked_input_submit", .response = runtimeStringValue("clicked_input_submit"), .expected = true },
        .{ .name = "clicked_fallback_button", .response = runtimeStringValue("clicked_fallback_button"), .expected = true },
        .{ .name = "submitted", .response = runtimeStringValue("submitted"), .expected = true },
        .{ .name = "success", .response = runtimeStringValue("success"), .expected = true },
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
    try std.testing.expect(!audio_bypass.shouldContinueAudioChallengeLoop(.{
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

test "audio_bypass: challenge loop uses successful target not static count" {
    try std.testing.expect(audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 2,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = false,
    }));

    try std.testing.expect(!audio_bypass.shouldContinueAudioChallengeLoop(.{
        .successful_submits = 3,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = false,
    }));
}

test "audio_bypass: final success is true when runtime target submissions reached" {
    try std.testing.expect(audio_bypass.audioBypassFinalSuccess(.{
        .successful_submits = 3,
        .attempted = 3,
        .target_challenges = 3,
        .challenge_complete = false,
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
