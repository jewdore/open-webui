<script lang="ts">
	import { getContext } from 'svelte';
	import Textarea from '$lib/components/common/Textarea.svelte';
	import Tooltip from '$lib/components/common/Tooltip.svelte';

	const i18n = getContext('i18n');

	export let name = '';
	export let color = '';
	export let description = '';

	export let meta = {};
</script>

<div class="flex gap-2">
	<div class="flex flex-col w-full">
		<div class=" mb-0.5 text-xs text-gray-500">{$i18n.t('Name')}</div>

		<div class="flex-1">
			<input
				class="w-full text-sm bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none"
				type="text"
				bind:value={name}
				placeholder={$i18n.t('Group Name')}
				autocomplete="off"
				required
			/>
		</div>
	</div>
</div>

<!-- <div class="flex flex-col w-full mt-2">
	<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Color')}</div>

	<div class="flex-1">
		<Tooltip content={$i18n.t('Hex Color - Leave empty for default color')} placement="top-start">
			<div class="flex gap-0.5">
				<div class="text-gray-500">#</div>

				<input
					class="w-full text-sm bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none"
					type="text"
					bind:value={color}
					placeholder={$i18n.t('Hex Color')}
					autocomplete="off"
				/>
			</div>
		</Tooltip>
	</div>
</div> -->

<div class="flex flex-col w-full mt-2">
	<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Description')}</div>

	<div class="flex-1">
		<Textarea
			className="w-full text-sm bg-transparent placeholder:text-gray-300 dark:placeholder:text-gray-700 outline-none resize-none"
			rows={4}
			bind:value={description}
			placeholder={$i18n.t('Group Description')}
		/>
	</div>
</div>

<div class="flex flex-col w-full mt-2">
	<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Knowledge')}</div>
	<div class="flex gap-1.5">
		<div class=" self-center text-xs font-medium min-w-fit mb-1">
			{$i18n.t('Max Upload Size')}
		</div>

		<div class="self-center">
			<Tooltip
				content={$i18n.t(
					'The maximum file size in MB. If the file size exceeds this limit, the file will not be uploaded.'
				)}
				placement="top-start"
			>
				<input
					class="w-full rounded-lg py-1.5 px-4 text-sm bg-gray-50 dark:text-gray-300 dark:bg-gray-850 outline-none"
					type="number"
					placeholder={$i18n.t('Leave empty for unlimited')}
					bind:value={meta.fileMaxSize}
					autocomplete="off"
					min="0"
				/>
			</Tooltip>
		</div>
	</div>

	<div class="flex gap-1.5">
		<div class="self-center text-xs font-medium min-w-fit mb-1">
			{$i18n.t('Max Upload Count')}
		</div>
		<div class="self-center">
			<Tooltip
				content={$i18n.t(
					'The maximum number of files that can be used at once in chat. If the number of files exceeds this limit, the files will not be uploaded.'
				)}
				placement="top-start"
			>
				<input
					class=" w-full rounded-lg py-1.5 px-4 text-sm bg-gray-50 dark:text-gray-300 dark:bg-gray-850 outline-none"
					type="number"
					placeholder={$i18n.t('Leave empty for unlimited')}
					bind:value={meta.fileMaxCount}
					autocomplete="off"
					min="0"
				/>
			</Tooltip>
		</div>
	</div>
</div>